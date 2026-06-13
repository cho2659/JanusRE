# Task M000 #9 공유 메모리 ABI

## 목적

Frida agent와 Python worker 사이의 trace 제어와 이벤트 전달을 RPC/JSON 대신 Windows named shared memory로 처리한다. Python은 메모리 layout과 lifetime을 소유하고, agent는 bootstrap 상수로 mapping을 열어 고정 크기 binary record를 기록한다.

## Bootstrap

Python은 `agent.js` 로드 전에 다음 placeholder를 치환한다.

| 이름 | 의미 |
|---|---|
| `FRIDA_DELTA_SHM_NAME` | Windows named file mapping 이름. 예: `Local\\frida_delta_{pid}_{nonce}` |
| `FRIDA_DELTA_SHM_SIZE` | mapping 전체 byte 크기 |
| `FRIDA_DELTA_WAKE_EVENT_NAME` | ring buffer 위험 수위 도달 시 agent가 signal할 Windows Event Object 이름 |
| `FRIDA_DELTA_MAIN_PID` | spawn된 main process pid |
| `FRIDA_DELTA_MAIN_TID` | resume 전 Python이 열거한 main thread id |

agent는 RPC를 export하지 않는다. 시작 config와 stop command는 모두 shared memory header를 통해 읽는다.

## 전체 Layout

모든 multi-byte field는 little-endian이다. header와 record는 8-byte alignment를 기준으로 한다.

| 영역 | Offset | 크기 | 소유자 | 설명 |
|---|---:|---:|---|---|
| Header | `0x0000` | `0x0100` | Python 초기화, 양쪽 갱신 | 상태, 인덱스, config 위치 |
| Module table | `module_table_offset` | `module_record_size * module_count` | Python | target module config |
| Function-start bitmap | `function_bitmap_offset` | `function_bitmap_size` | Python | module별 함수 시작점 bitset |
| Callout data arena | `callout_arena_offset` | `callout_arena_size` | agent atomic bump | Stalker callout user data |
| Event ring 0 | `event_ring0_offset` | `record_size * record_capacity` | agent write, Python read | trace event records |
| Event ring 1 | `event_ring1_offset` | `record_size * record_capacity` | agent write, Python read | double buffering용 보조 ring |

## Header v1

| Offset | Type | Field |
|---:|---|---|
| `0x00` | `u32` | magic: `0x46445348` (`FDSH`) |
| `0x04` | `u16` | version: `1` |
| `0x06` | `u16` | header_size: `0x100` |
| `0x08` | `u32` | state |
| `0x0C` | `u32` | command |
| `0x10` | `u32` | config_flags |
| `0x14` | `u32` | last_error |
| `0x18` | `u32` | main_pid |
| `0x1C` | `u32` | main_tid |
| `0x20` | `u64` | seq_counter |
| `0x28` | `u64` | write_index |
| `0x30` | `u64` | read_index |
| `0x38` | `u64` | dropped_count |
| `0x40` | `u32` | record_size |
| `0x44` | `u32` | record_capacity |
| `0x48` | `u32` | module_table_offset |
| `0x4C` | `u32` | module_count |
| `0x50` | `u32` | module_record_size |
| `0x54` | `u32` | function_bitmap_offset |
| `0x58` | `u32` | function_bitmap_size |
| `0x5C` | `u32` | callout_arena_offset |
| `0x60` | `u32` | callout_arena_size |
| `0x64` | `u32` | callout_arena_write_offset |
| `0x68` | `u32` | event_ring0_offset |
| `0x6C` | `u32` | status_code |
| `0x70` | `u64` | oep_observed_at_seq |
| `0x78` | `u32` | event_ring1_offset |
| `0x7C` | `u32` | active_write_buffer |
| `0x80` | `u32` | active_read_buffer |
| `0x84` | `u32` | high_watermark_percent |
| `0x88` | `u64` | wake_event_signal_count |
| `0x90` | `u64` | blocking_wait_count |
| `0x98` | `u64` | reserved |

`write_index`, `seq_counter`, `callout_arena_write_offset`, `state` 전환은 agent의 atomic helper가 갱신한다. Python은 `read_index`, `command`를 갱신한다.

## Config Flags

| Bit | 이름 | 의미 |
|---:|---|---|
| `0` | `BLOCK_ON_FULL` | ring buffer가 꽉 차면 agent writer thread가 Python reader 진행을 기다린다. 무결성 모드다. |
| `1` | `DOUBLE_BUFFERING` | event ring 0/1을 번갈아 사용한다. |
| `2` | `WAKE_ON_HIGH_WATERMARK` | 사용량이 `high_watermark_percent` 이상이면 Windows Event Object를 signal한다. 기본 80%. |

기본값은 `DOUBLE_BUFFERING | WAKE_ON_HIGH_WATERMARK`다. `BLOCK_ON_FULL`은 데이터 무결성이 정지 리스크보다 중요할 때만 켠다.

## State

| 값 | 이름 | 의미 |
|---:|---|---|
| `0` | `INIT` | Python이 mapping을 만들었지만 config 준비 전 |
| `1` | `CONFIG_READY` | module/function bitmap 준비 완료 |
| `2` | `SCRIPT_READY` | agent가 mapping 검증 완료 |
| `3` | `OEP_READY` | main PID/main TID에서 OEP 완료 신호 확인 |
| `4` | `RUNNING` | thread scan 이후 event 기록 중 |
| `5` | `STOP_REQUESTED` | Python stop 요청 |
| `6` | `STOPPED` | agent cleanup 완료 |
| `7` | `ERROR` | agent 또는 Python 오류 |

OEP gate는 `CONFIG_READY` 또는 `SCRIPT_READY`에서 `OEP_READY`로 compare-exchange한다. 이 전이는 `Process.id == main_pid`이고 `Process.getCurrentThreadId() == main_tid`일 때만 허용한다.

## Command

| 값 | 이름 | 의미 |
|---:|---|---|
| `0` | `NONE` | 명령 없음 |
| `1` | `STOP` | Python이 agent cleanup 요청 |

agent는 hot path에서 command를 매번 보지 않는다. periodic callback, receive callback, stop-sensitive hook에서 확인한다.

## Module Record

`module_record_size = 48`.

| Offset | Type | Field |
|---:|---|---|
| `0x00` | `u64` | base |
| `0x08` | `u64` | size |
| `0x10` | `u32` | name_hash |
| `0x14` | `u32` | flags |
| `0x18` | `u32` | function_bitmap_offset |
| `0x1C` | `u32` | function_bitmap_bits |
| `0x20` | `u64` | reserved0 |
| `0x28` | `u64` | reserved1 |

module name 문자열은 hot path에 두지 않는다. Python은 base/size와 name_hash를 관리하고, event 후처리에서 VA를 module/offset으로 보강한다.

## Event Record v1

`record_size = 64`.

| Offset | Type | Field |
|---:|---|---|
| `0x00` | `u16` | kind: `0=call`, `1=ret`, `2=jump`, `3=module`, `4=thread`, `5=exception`, `6=status` |
| `0x02` | `u16` | flags |
| `0x04` | `u32` | tid |
| `0x08` | `u64` | seq |
| `0x10` | `u64` | src |
| `0x18` | `u64` | dst |
| `0x20` | `u64` | aux0 |
| `0x28` | `u64` | aux1 |
| `0x30` | `u64` | aux2 |
| `0x38` | `u64` | timestamp_or_reserved |

call/ret/jump record는 `src`, `dst`, `tid`, `seq`, `flags`만 필수로 쓴다. `src_tt`, `dst_tt`, `is_jump` 같은 값은 flags bit로 표현한다.

## Ring Buffer

agent writer:

1. `seq = atomic_fetch_add(seq_counter, 1)`
2. `slot = atomic_fetch_add(write_index, 1)`
3. `slot - read_index >= record_capacity`이면 `dropped_count`를 증가시키고 기록하지 않는다.
4. record 위치는 `event_ring{active_write_buffer}_offset + (slot % record_capacity) * record_size`.
5. 사용량이 `record_capacity * high_watermark_percent / 100` 이상이면 `FRIDA_DELTA_WAKE_EVENT_NAME` event를 signal한다.
6. `BLOCK_ON_FULL`이 켜져 있고 ring이 full이면 writer는 Python이 `read_index`를 전진시킬 때까지 짧게 wait한다.

Python reader:

1. `write_index` snapshot을 읽는다.
2. `read_index < write_index` 동안 record를 읽는다.
3. 읽은 count만큼 `read_index`를 갱신한다.
4. 위험 수위 event를 wait하고 깨어나면 즉시 drain한다. periodic poll은 fallback으로만 둔다.
5. double buffering이 켜져 있고 active write ring이 포화에 가까우면 Python은 drain 완료 후 active read/write buffer 전환을 허용한다.

초기 구현은 단일 agent writer 관점으로 시작하되, Stalker callback이 여러 thread에서 동시에 들어올 수 있으므로 write index와 seq는 반드시 atomic operation으로 갱신한다.

## Agent Allocation Policy

agent trace 수집 경로에서 `Memory.alloc`을 호출하지 않는다.

- classifier table은 shared memory의 module table을 직접 참조한다.
- function-start bitmap은 shared memory bitmap 영역을 직접 참조한다.
- Stalker callout user data는 shared memory callout arena에서 atomic bump로 할당한다.
- callout arena가 부족하면 해당 callout 삽입을 생략하거나 null user_data를 사용하고 status/drop counter를 증가시킨다.

## Python 후처리

Python은 event record를 기존 raw event dict로 변환한다.

| Record | Dict |
|---|---|
| `kind` | `k` |
| `src`, `dst` | hex string |
| `tid` | integer |
| `seq` | integer |
| `flags` | `src_tt`, `dst_tt`, `is_jump` 등으로 해석 |

module name, offset, symbol은 기존 `postprocess()` 또는 동등한 Python 경로에서 VA 기준으로 보강한다.
