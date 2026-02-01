# Controller Team: Connection Fix Instructions

**From**: p-net analysis (pcap-verified, code-traced)
**Date**: 2026-01-31
**Scope**: Water-Controller repo (`mwilco03/Water-Controller`)

---

## Execution Order

Do not skip ahead. Each phase builds on the previous one.

| Phase | Goal | Validates |
|-------|------|-----------|
| 0 | Fix wire-level encoding bugs | RPC header, block headers, tag fields |
| 1 | DAP-only connect | Proves encoding is correct end-to-end |
| 2 | GSDML-based full connect | All slots from parsed GSDML |
| 3 | ModuleDiffBlock tolerance | Handles mismatched/missing modules |
| 4 | HTTP fallback (non-standard) | Insurance when GSDML unavailable |

---

## Phase 0: Fix Wire-Level Bugs

These five bugs were identified from raw hex analysis of `profi.pcapng`.
Every brute force variant fails due to at least one of these.

### Bug 0.1: ARBlockReq block_length includes padding (BLOCKING)

**File**: `src/profinet/profinet_rpc.c`
**Lines**: 469-479

**Current code** (broken):
```c
469    size_t name_len = strlen(params->station_name);
470    write_u16_be(buffer, (uint16_t)name_len, &pos);
471    memcpy(buffer + pos, params->station_name, name_len);
472    pos += name_len;
473    align_to_4(&pos);                    // padding included in pos
474
475    /* Fill AR block header */
476    size_t ar_block_len = pos - ar_block_start - 4;  // INCLUDES padding
477    size_t save_pos = ar_block_start;
478    write_block_header(buffer, BLOCK_TYPE_AR_BLOCK_REQ,
479                        (uint16_t)ar_block_len, &save_pos);
```

**Problem**: `align_to_4()` at line 473 advances `pos` before `ar_block_len` is
calculated at line 476. For station name "rtu-4b64" (8 bytes), the content is
52 + 8 = 60 bytes + 2 bytes version = 62. But `align_to_4` adds 2 padding bytes,
making block_length = 64.

p-net validates at `pf_cmrpc.c:1176`:
```c
if (p_block_header->block_length != block_length)  // 64 != 62 -> FAIL
```

Expected block_length = `54 + strlen(station_name)`.

**Fix**: Calculate block_length BEFORE alignment padding, then **remove** the
inter-block `align_to_4()` entirely:
```c
469    size_t name_len = strlen(params->station_name);
470    write_u16_be(buffer, (uint16_t)name_len, &pos);
471    memcpy(buffer + pos, params->station_name, name_len);
472    pos += name_len;
473
474    /* Fill AR block header — NO alignment padding after */
475    size_t ar_block_len = pos - ar_block_start - 4;
476    size_t save_pos = ar_block_start;
477    write_block_header(buffer, BLOCK_TYPE_AR_BLOCK_REQ,
478                        (uint16_t)ar_block_len, &save_pos);
479
480    /* Next block starts immediately — do NOT call align_to_4(&pos) here.
481     * See Bug 0.7 for why inter-block padding must not be written. */
```

**Verification**: For station name "rtu-4b64": block_length should be
54 + 8 = 62 = 0x003E. Check wire bytes at offset 2-3 of ARBlockReq: `00 3E`.

---

### Bug 0.2: AlarmCRBlockReq tag headers are zero (BLOCKING)

**File**: `src/profinet/profinet_rpc.c`
**Lines**: 584-585

**Current code** (broken):
```c
584    write_u16_be(buffer, 0, &pos);  /* Tag header high */
585    write_u16_be(buffer, 0, &pos);  /* Tag header low */
```

**Problem**: PROFINET requires VLAN priority tags in the AlarmCR block.
- `tag_header_high` = 0xC000 (VLAN priority 6, vlan_id 0)
- `tag_header_low` = 0xA000 (VLAN priority 5, vlan_id 0)

p-net **rejects 0x0000**. The validation is in `pf_cmdev.c:4088-4098`:
```c
if (p_ar->alarm_cr_request.alarm_cr_tag_header_high.alarm_user_priority != 6)
{
   pf_set_error(p_stat, ..., PNET_ERROR_CODE_1_CONN_FAULTY_ALARM_BLOCK_REQ, 11);
   ret = -1;
}
```
The uint16 is decoded as: bits 0-11 = vlan_id (must be 0), bits 13-15 = priority.
0x0000 → priority=0 → rejected with error code 11/12.
0xC000 → priority=6 → accepted. 0xA000 → priority=5 → accepted.

**Fix**:
```c
584    write_u16_be(buffer, 0xC000, &pos);  /* Tag header high (VLAN prio 6) */
585    write_u16_be(buffer, 0xA000, &pos);  /* Tag header low  (VLAN prio 5) */
```

---

### Bug 0.3: Verify RPC header byte order matches platform assumption

**File**: `src/profinet/profinet_rpc.c`
**Lines**: 194-206

**Current code**:
```c
195    hdr->server_boot = 0;
196    hdr->interface_version = 1;
197    hdr->sequence_number = ctx->sequence_number;
...
203    hdr->fragment_length = fragment_length;
```

**Assessment**: This uses direct struct assignment, which produces LE on LE platforms
(x86, ARM). Since `drep=0x10` declares LE, this is correct IF AND ONLY IF the
controller runs on a little-endian CPU.

The pcap showed some brute force frames with BE-encoded RPC fields (e.g.,
`if_version` as `00 00 00 01` instead of `01 00 00 00`). If the current code
produces correct LE output, then the pcap was captured from an older version.

**Action**: Add a compile-time assertion:
```c
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
               "RPC header relies on LE platform; use explicit conversion for BE");
```

If the controller ever needs to run on a BE platform, all these fields need
explicit LE conversion.

---

### Bug 0.4: NDR header must always be present

**File**: `src/profinet/profinet_rpc.c`
**Lines**: 264-316 (NDR writer)

**Context**: The 48-strategy system (`rpc_strategy.c`) was a debugging tool
to find a working wire format by brute force. Now that the correct format is
identified, the strategy cycling should be retired and replaced with a single
correct implementation.

p-net REQUIRES NDR. From `pf_cmrpc.c:4622-4634`:
```c
if (pf_get_ndr_data_req(&p_sess->get_info, &req_pos, &p_sess->ndr_data) != 0)
{
   LOG_ERROR(PF_RPC_LOG, "CMRPC(%d): Invalid NDR header.\n", __LINE__);
   ret = -1;
}
```

**Fix**: Always include the 20-byte NDR header. The correct wire format is:
- `UUID_WIRE_SWAP_FIELDS` (LE encoding per DREP=0x10)
- NDR always present
- `OPNUM_STANDARD` (0 = Connect)

The strategy system served its diagnostic purpose. The production code path
should use the single known-good format directly, not cycle through 48
combinations that include intentionally broken variants.

---

### Bug 0.5: ARBlockReq trailing buffer bytes

**File**: `src/profinet/profinet_rpc.c`
**Lines**: 471-473

The pcap shows 2 garbage bytes (`7B 32`) after the station name within the
ARBlockReq. These are the last 2 bytes of CMInitiatorObjectUUID that leaked
into the station name area. This is a consequence of Bug 0.1 — `align_to_4()`
advances `pos` into buffer space that wasn't explicitly zeroed.

**Fix**: With Bug 0.1 fixed (block_length excludes padding) and Bug 0.7
applied (no inter-block padding), this bug is eliminated. There are no
alignment padding bytes to contain garbage, because no alignment padding
is written. The station name ends and the next block header begins
immediately.

~~The original fix suggested zeroing padding bytes. That fix is superseded
by Bug 0.7: do not write inter-block padding at all.~~

---

### Bug 0.6: Interface UUID must not be byte-swapped (BLOCKING — SILENT DROP)

**File**: `src/profinet/profinet_rpc.c` (two locations where Interface UUID is written)

**Root cause**: When the 48-strategy system was retired (Bug 0.4), `uuid_swap_fields()`
was applied to ALL three RPC header UUIDs: Object, Interface, and Activity. But the
Interface UUID constants (`PNIO_DEVICE_INTERFACE_UUID`, `PNIO_CONTROLLER_INTERFACE_UUID`)
must NOT be swapped. They are protocol constants stored in canonical byte order — the
same byte order p-net uses internally.

**Why it fails**: p-net parses the Interface UUID from the wire using DREP-aware functions
(`pf_get_uuid()` at `pf_block_reader.c:922`, which uses `pf_get_uint32()`/`pf_get_uint16()`
respecting `is_big_endian` from `pf_block_reader.c:910`). This converts wire bytes back
to host-order `pf_uuid_t` values. Then at `pf_cmrpc.c:4690`, a raw `memcmp` compares the
parsed UUID against the constant:

```c
4690    if (
4691       memcmp (
4692          &rpc_req.interface_uuid,
4693          &uuid_io_device_interface,      /* {0xDEA00001, 0x6C97, 0x11D1, ...} */
4694          sizeof (rpc_req.object_uuid)) == 0)
```

If `uuid_swap_fields()` byte-swaps data1/data2/data3 before LE serialization, the wire
gets BE-ordered bytes. p-net's LE parser then converts those back to the swapped form
(`{0x0100A0DE, 0x976C, 0xD111, ...}`). The `memcmp` fails — the UUID is not recognized
as PNIO or EPM.

**Why it's silent**: When neither PNIO nor EPM UUID matches, p-net falls through to
`pf_cmrpc.c:4749-4756`:

```c
4749    else
4750    {
4751       LOG_ERROR (PF_RPC_LOG,
4752          "CMRPC(%d): Unhandled Object or Interface UUID!\n", __LINE__);
4753       /*ToDo: Report NULL endpoint with proper error code*/
4754    }
```

No response body is generated. The controller gets nothing back — no error, no reject,
just silence. This made the bug invisible during strategy cycling because the system
already expected most strategies to fail.

**Fix**: Remove `uuid_swap_fields()` from the two locations where Interface UUID
constants are written. Object UUID and Activity UUID (session-specific, generated at
runtime in host order) still need the swap for LE wire encoding. Interface UUID constants
do not.

```c
/* Object UUID — swap for LE wire encoding (session-specific) */
uuid_swap_fields(&object_uuid);
write_uuid(buffer, &object_uuid, &pos);

/* Interface UUID — DO NOT swap (protocol constant, matches p-net's internal form) */
write_uuid(buffer, &PNIO_DEVICE_INTERFACE_UUID, &pos);

/* Activity UUID — swap for LE wire encoding (session-specific) */
uuid_swap_fields(&activity_uuid);
write_uuid(buffer, &activity_uuid, &pos);
```

**Verification**: After fix, p-net must respond (not silence). Even an error response
with `frag_len >= 20` confirms the Interface UUID matched.

---

### Bug 0.7: No inter-block alignment padding (BLOCKING — UNKNOWN BLOCKS)

**File**: `src/profinet/profinet_rpc.c` (every location where `align_to_4()` is
called between blocks in the connect request builder)

**Root cause**: The connect request builder calls `align_to_4(&pos)` between
blocks (e.g., after ARBlockReq before IOCRBlockReq, after IOCRBlockReq before
ExpectedSubmoduleBlockReq, etc.). This writes zero-fill padding bytes to make
the next block start on a 4-byte boundary. p-net's block parser does not expect
or skip these bytes.

**Why it fails**: p-net's connect request parser (`pf_cmrpc.c:1232-1704`) loops
through blocks by reading `pf_get_block_header()`, parsing the block content
(which advances `*p_pos` by exactly the bytes consumed), then immediately reading
the next block header. There is no alignment skip between iterations.

p-net's own connect response writer (`pf_cmrpc.c:1840-1855`) confirms this: it
calls `pf_put_ar_result()` then `pf_put_iocr_result()` with no padding between
them. ARBlockRes is 34 bytes (34 % 4 = 2), yet the next block starts at byte 35.

When the controller writes 2 bytes of `align_to_4` padding after a block, p-net
reads those zeros as the next `block_type = 0x0000`. This value is not in the
block type switch (`pf_cmrpc.c:1242`), so it hits the default case at line 1673:

```c
default:
    LOG_DEBUG(PF_RPC_LOG, "CMRPC(%d): Unknown block type %u\n",
        __LINE__, block_header.block_type);
    pf_set_error(&p_sess->rpc_result, PNET_ERROR_CODE_CONNECT,
        PNET_ERROR_DECODE_PNIO, PNET_ERROR_CODE_1_CMRPC,
        PNET_ERROR_CODE_2_CMRPC_UNKNOWN_BLOCKS);
```

Wireshark decodes this error as: `Connect response, Error: "IODConnectRes",
"PNIO", "CMRPC", "Unknown Blocks"`.

**Example**: For station name "rtu-4b64" (8 bytes):
- ARBlockReq total: 4 (header) + 62 (block_length) = 66 bytes
- 66 % 4 = 2, so `align_to_4` writes 2 zero bytes
- p-net's parser finishes ARBlockReq at byte 66, reads `block_type = 0x0000`
  from the padding → "Unknown block type 0"

**Fix**: Remove ALL `align_to_4(&pos)` calls between blocks in the connect
request builder. Blocks are concatenated directly with no gaps. This applies to
every block boundary, not just ARBlockReq:

```c
/* ARBlockReq */
write_ar_block(buffer, &pos);
/* Do NOT call align_to_4(&pos) */

/* IOCRBlockReq (Input) */
write_iocr_block(buffer, &pos, INPUT);
/* Do NOT call align_to_4(&pos) */

/* IOCRBlockReq (Output) */
write_iocr_block(buffer, &pos, OUTPUT);
/* Do NOT call align_to_4(&pos) */

/* ExpectedSubmoduleBlockReq */
write_expected_submodule_block(buffer, &pos);
/* Do NOT call align_to_4(&pos) */

/* AlarmCRBlockReq */
write_alarm_cr_block(buffer, &pos);
```

**Note**: Alignment padding IS used WITHIN blocks for internal field alignment
(e.g., per PROFINET spec, some fields must be uint32-aligned). This is fine —
intra-block padding is counted in `block_length` and consumed by the parser.
What must NOT exist is padding BETWEEN blocks.

**Verification**: In a hex dump, the byte immediately after a block's content
(at offset `block_start + 4 + block_length`) must be `0x01` (the high byte of
the next block_type, since all connect request block types are `0x01xx`). If
you see `0x00` at that position, inter-block padding is still present.

---

### Phase 0 Completion Summary

All seven controller-side bugs have been identified. Seven additional
issues were found and fixed on the RTU side (Water-treat repo):

| # | RTU Fix | Detail |
|---|---------|--------|
| 1 | Record Read 0xF844 not implemented | Built `profinet_manager_build_slot_map()` returning BE-packed binary (2-byte header + 15 bytes/slot). Full step 5 of discovery chain now operational. |
| 2 | Write callback silent success on unknown vendor indices | Unknown indices >0x7FFF now return PNIO error 0xDE/0x80 instead of silently succeeding. |
| 3 | `slots_to_json` slot_count mismatch | `slot_count` now reflects actual emitted entries if buffer truncation occurs, with warning log. |
| 4 | `serve_gsdml_file` fire-and-forget send | Proper partial-send loop with `MSG_NOSIGNAL`, error logging, and clean fd/fp cleanup on failure. |
| 5 | Config sync not forwarded in stub mode | 0xF841-0xF843 now forwarded in `!HAVE_PNET` builds, matching `user_sync` and enrollment forwarding. |
| 6 | Build broken — missing `user_sync_protocol.h` | Fetched from Water-Controller repo via `scripts/fetch_shared_protocols.sh`. |
| 7 | Test build broken | Added `tests/test_stubs.c` for TUI stubs, fixed `test_framework.h` unused variable warnings. |

---

## Phase 1: DAP-Only Connect

After fixing Phase 0 bugs, test with the simplest possible connect request:
only DAP at slot 0, no application modules.

### What to send

**ExpectedSubmoduleBlockReq** with 1 API, 1 slot, 3 submodules:

```
API: 0x00000000
  Slot 0, ModuleIdent 0x00000001 (DAP)
    Subslot 0x0001, SubmoduleIdent 0x00000001 (DAP identity)
    Subslot 0x8000, SubmoduleIdent 0x00000100 (Interface)
    Subslot 0x8001, SubmoduleIdent 0x00000200 (Port)
```

These idents come from the RTU's GSDML (`GSDML-V2.4-WaterTreat-RTU-20241222.xml`):
- Line 95: DAP submodule = 0x00000001
- Line 116: Interface submodule = 0x00000100 at subslot 32768 (0x8000)
- Line 130: Port submodule = 0x00000200 at subslot 32769 (0x8001)

**NOTE**: The controller code in `gsdml_modules.h` already has the correct defines:
```c
#define GSDML_MOD_DAP           0x00000001
#define GSDML_SUBMOD_DAP        0x00000001
#define GSDML_SUBMOD_INTERFACE  0x00000100
#define GSDML_SUBMOD_PORT       0x00000200
```

These match the RTU code in `profinet_manager.c:885-919` and the GSDML.

### IOCRBlockReq for DAP-only

DAP has no IO data (PNET_DIR_NO_IO, input_size=0, output_size=0).
IOCRBlockReq still required but with minimal data lengths:

- Input IOCR: `data_length` = 40 (minimum c_sdu_length for RT_CLASS_1)
- Output IOCR: `data_length` = 40

**Note**: The wire field `data_length` in IOCRBlockReq maps directly to p-net's
internal `c_sdu_length` field (`pf_block_reader.c:438`). No transformation.
The 40-byte minimum is the PROFINET spec floor for RT_CLASS_1/2/3 frames,
enforced at `pf_cmdev.c:3095-3102`. DAP's actual IO payload is 0 bytes —
the frame is padded to 40.

Frame IDs:
- Input: 0xC001 (RT_CLASS_1 range: 0xC000-0xF7FF, validated at `pf_cmdev.c:3136`)
- Output: 0xFFFF (let device assign from 0xC000-0xF7FF via `pf_cmdev.c:4680`)

**CORRECTION**: The previous version listed Output=0x8001. That's wrong.
0x8000-0xBBFF is the RT_CLASS_2 range. For RT_CLASS_1, both input and output
use 0xC000-0xF7FF. The standard practice for OUTPUT IOCR is to send 0xFFFF
and let the device (p-net) assign a frame_id from the valid range. p-net does
this in `pf_cmdev_fix_frame_id()` at `pf_cmdev.c:4660-4698`.

The pcap values (0x8002/0x8003) were also wrong — same problem, RT_CLASS_2
range used for RT_CLASS_1. p-net validates INPUT frame_id at
`pf_cmdev.c:3132-3149` and would reject 0x8002.

### IOCRBlockReq API entries

Each IOCR needs API entries listing which submodules contribute data:

```
Input IOCR:
  API 0x00000000, 3 IODataObjects:
    Slot 0 Subslot 0x0001 FrameOffset 0
    Slot 0 Subslot 0x8000 FrameOffset 0
    Slot 0 Subslot 0x8001 FrameOffset 0
  3 IOCS entries (same slots/subslots)

Output IOCR:
  API 0x00000000, 3 IODataObjects:
    Slot 0 Subslot 0x0001 FrameOffset 0
    Slot 0 Subslot 0x8000 FrameOffset 0
    Slot 0 Subslot 0x8001 FrameOffset 0
  3 IOCS entries (same slots/subslots)
```

### Strategy for Phase 1

Use exactly one strategy (no brute force):
- `UUID_WIRE_SWAP_FIELDS` (LE encoding per DREP)
- `NDR_REQUEST_PRESENT` (mandatory)
- `SLOT_SCOPE_DAP_ONLY`
- `TIMING_CONSERVATIVE` (relaxed timing for initial testing)
- `OPNUM_STANDARD` (0 = Connect)

### Expected response

If encoding is correct, p-net returns a Connect Response with:
- ARBlockRes (AR accepted)
- IOCRBlockRes (IOCR accepted)
- ModuleDiffBlock showing DAP matches

If ModuleDiffBlock shows all modules as `MODULE_STATE_PROPER`, the connect
succeeded. Proceed to Phase 2.

### What to verify in the response

1. Response `frag_len > 20` (not just an error)
2. ARBlockRes present (block_type 0x8101)
3. No PNIO error codes in the response

---

## Phase 2: GSDML-Based Full Connect

### Approach

Parse the GSDML XML file (`GSDML-V2.4-WaterTreat-RTU-20241222.xml`) to
build ExpectedSubmoduleBlockReq with all possible modules. The controller
should ship with (or fetch) this file — it does NOT need an HTTP API.

The GSDML defines these module types as usable in slots 1-246:

| Module | Ident (hex) | Ident (dec) | Submodule (hex) | Submodule (dec) | Direction | Data Size |
|--------|-------------|-------------|-----------------|-----------------|-----------|-----------|
| pH | 0x00000010 | 16 | 0x00000011 | 17 | INPUT | 5 bytes |
| TDS | 0x00000020 | 32 | 0x00000021 | 33 | INPUT | 5 bytes |
| Turbidity | 0x00000030 | 48 | 0x00000031 | 49 | INPUT | 5 bytes |
| Temperature | 0x00000040 | 64 | 0x00000041 | 65 | INPUT | 5 bytes |
| Flow | 0x00000050 | 80 | 0x00000051 | 81 | INPUT | 5 bytes |
| Level | 0x00000060 | 96 | 0x00000061 | 97 | INPUT | 5 bytes |
| Generic AI | 0x00000070 | 112 | 0x00000071 | 113 | INPUT | 5 bytes |
| Pump | 0x00000100 | 256 | 0x00000101 | 257 | OUTPUT | 4 bytes |
| Valve | 0x00000110 | 272 | 0x00000111 | 273 | OUTPUT | 4 bytes |
| Generic DO | 0x00000120 | 288 | 0x00000121 | 289 | OUTPUT | 4 bytes |

**Note**: Hex values are used in C code (`gsdml_modules.h` defines) and GSDML.
Decimal values appear in the HTTP `/api/v1/slots` JSON response and the SQLite
database. They are the same numbers: `0x10 == 16`, `0x100 == 256`.

### Building ExpectedSubmoduleBlockReq

The controller does NOT know which modules the RTU has plugged until the
Connect Response (ModuleDiffBlock). Two approaches:

**Approach A (Recommended)**: Send only DAP in ExpectedSubmoduleBlockReq.
Read the ModuleDiffBlock. If it shows MODULE_STATE_NO_MODULE for all
application slots, use Record Read 0xF844 (RealIdentificationData) to
discover what's actually plugged. Then release and reconnect with correct
layout.

**Approach B**: If the controller has prior knowledge (e.g., from a previous
successful connection, cached config, or user configuration through the HMI),
send the full expected layout. Handle ModuleDiffBlock for any mismatches.

### IOCRBlockReq data_length calculation

For each IOCR, sum the data sizes of all contributing submodules:

```
input_total  = sum of input_size for all INPUT submodules
output_total = sum of output_size for all OUTPUT submodules

Input IOCR data_length  = 40 + input_total + (number_of_input_submodules * 1)
Output IOCR data_length = 40 + output_total + (number_of_output_submodules * 1)
```

The `+1` per submodule accounts for the IOPS/IOCS byte per submodule in the
cyclic frame.

### File changes

**`src/profinet/profinet_rpc.c`** — ExpectedSubmoduleBlock builder (lines 592-672):
The current code at line 608 already iterates `params->expected_config[]`.
Ensure the caller populates this array from GSDML (not hardcoded).

**`src/registry/slot_manager.c`** — This is where slot configs are created.
Verify it builds `expected_config[]` dynamically from either:
- GSDML parse results
- Cached previous connection state
- User HMI configuration

---

## Phase 3: ModuleDiffBlock Tolerance

After a full connect, the response includes ModuleDiffBlock (block_type 0x8104)
listing module states:

| State | Value | Meaning | Action |
|-------|-------|---------|--------|
| MODULE_STATE_PROPER | 0x0000 | Module matches | Normal operation |
| MODULE_STATE_SUBSTITUTE | 0x0001 | Slot empty | Mark slot inactive, skip in IO map |
| MODULE_STATE_WRONG | 0x0002 | Different module | Use actual module's data format |
| MODULE_STATE_NO_MODULE | 0x0003 | Nothing plugged | Mark slot inactive |

### Rules

1. **DAP diff IS fatal** — if slot 0 doesn't match, abort and investigate
2. **Application module diff is NOT fatal** — adapt IO map at runtime
3. Log every diff at WARNING level
4. Update the slot manager's runtime config to reflect actual state
5. Recalculate cyclic IO frame offsets based on actual plugged modules

### File changes

The ModuleDiffBlock parser should be in the connect response handler.
Currently the strategy system treats any non-success response as a failure
and advances to the next strategy. After Phase 0-2 fixes produce a successful
connect, add diff parsing to the response handler.

**`src/profinet/ar_manager.c`** — Add ModuleDiffBlock parsing to the
connect response handler. Map each diff entry to the slot manager.

---

## Phase 4: HTTP Fallback (Non-Standard)

### Architecture

Two HTTP endpoints are available on the RTU (both implemented in
`health_check.c`). Neither is standard PROFINET, but `/api/v1/gsdml`
delivers the standard device description — only the transport is non-standard.

| Endpoint | Returns | Priority | Why |
|----------|---------|----------|-----|
| `/api/v1/gsdml` | Raw GSDML XML | Fallback #2 | Standard data, non-standard transport. Cache locally → becomes fallback #1 next time. |
| `/api/v1/slots` | JSON slot list | Fallback #4 | Proprietary format. Only current config, not full module catalog. |

### `/api/v1/gsdml` — Preferred HTTP fallback

```
GET http://<rtu_ip>:9081/api/v1/gsdml
Content-Type: application/xml
```

Returns the raw GSDML XML file (~32KB, streamed in 4KB chunks).
Returns HTTP 404 if GSDML file not found on RTU filesystem.

**Controller-side usage:**
1. Fetch once, save to local cache (e.g., `/var/cache/water-controller/gsdml/<station_name>.xml`)
2. Parse with existing GSDML parser — same code path as a local file
3. Build ExpectedSubmoduleBlockReq from the module catalog
4. On next connection, local cache satisfies fallback #1 — no HTTP needed

This is the recommended HTTP fallback because it gives the full module
catalog, not just what's currently plugged.

### `/api/v1/slots` — Last HTTP fallback

The RTU team document (RTU_TEAM_INSTRUCTIONS.md, Section 2.2) contains the
full API contract. Both documents reference the same spec. Key points:

```
GET http://<rtu_ip>:9081/api/v1/slots
Content-Type: application/json
```

**Response format:**
```json
{
  "slot_count": 2,
  "slots": [
    {"slot": 1, "subslot": 1, "module_ident": 16, "submodule_ident": 17,
     "direction": "input", "data_size": 5},
    {"slot": 2, "subslot": 1, "module_ident": 256, "submodule_ident": 257,
     "direction": "output", "data_size": 4}
  ]
}
```

**Contract details** (see RTU doc for full field definitions):
- **Path**: `/api/v1/slots` (versioned, not `/slots`)
- **Idents**: Integer (decimal). 16 = pH sensor (0x10), 256 = Pump (0x100)
- **DAP**: NOT included. Slot 0 is always DAP — controller knows this from GSDML.
- **Source**: Database (`db_module_list()`), available before PROFINET init.
- **Direction**: `(module_ident & 0x100) != 0` → "output" (actuator), else "input" (sensor)
- **Errors**: HTTP 503 when database unavailable. Connection refused = not ready.

### Controller-side implementation

**`web/api/app/api/v1/discover.py`** — The `probe-ip` endpoint (line 902)
already calls RTU HTTP. Extend it to fetch `/api/v1/gsdml` first, then
`/api/v1/slots` as fallback.

**GSDML fetch path:**
```c
http_get(rtu_ip, 9081, "/api/v1/gsdml", &response);
if (response.status == 200) {
    save_to_cache(station_name, response.body);  // local file for next time
    parse_gsdml(response.body);                   // same path as local file
    return;                                       // → Phase 2
}
// 404 or unreachable → fall through to /api/v1/slots
```

**Slot JSON path** — Build ExpectedSubmoduleBlockReq from JSON response:
```c
for each slot in response.slots:
    expected_config[i].slot = slot.slot
    expected_config[i].subslot = slot.subslot
    expected_config[i].module_ident = slot.module_ident       // integer, use directly
    expected_config[i].submodule_ident = slot.submodule_ident // integer, use directly
    expected_config[i].is_input = (strcmp(slot.direction, "input") == 0)
    expected_config[i].data_size = slot.data_size
```

### Fallback chain pseudocode

```
1. Do we have a local GSDML for this device?
   YES → Parse GSDML, build full ExpectedSubmoduleBlockReq → Phase 2
   NO  → Continue

2. Can we fetch GSDML from RTU HTTP?
   GET /api/v1/gsdml
   200 → Save to local cache, parse GSDML → Phase 2
   404 or unreachable → Continue

3. Do we have cached slot config from a previous connection?
   YES → Use cached config → Phase 2
   NO  → Continue

4. Can we fetch slot list from RTU HTTP?
   GET /api/v1/slots
   200 with data → Build ExpectedSubmoduleBlockReq from JSON → Phase 2
   503 or empty  → Continue

5. Fall back to DAP-only connect → Phase 1
   After connect, Record Read 0xF844 for actual slot layout
   Release, rebuild ExpectedSubmoduleBlockReq, reconnect → Phase 2
```

**Note**: Step 2 feeds step 1 — once the GSDML is fetched and cached, all
future connections use the local file. The HTTP call is a one-time cost.

---

## DHCP / IP Address Handling

The controller documentation already states: "NEVER hardcode RTU IP addresses."
The controller discovers RTUs via DCP multicast, which works regardless of how
the RTU obtained its IP (DHCP or static).

**Do NOT use DCP Set to assign IP addresses.** The RTU's IP comes from the
network (DHCP) or its own static config. The controller reads it from the DCP
Identify Response and connects to whatever IP is reported.

Relevant code: `web/api/app/services/dcp_discovery.py` — DCP response parsing
extracts `device.ip_address` from the DCP response block (DCP_OPTION_IP).

**ACTION**: The Water-Controller repo's `CLAUDE.md` connection sequence diagram
shows "DCP Set (assign IP address)" at step 2. This contradicts the design
agreement. Update the diagram to show DCP Identify only — the controller
discovers the RTU's existing IP, it does not assign one. Remove or annotate
step 2 to read: "DCP Identify Response (read IP — do NOT use DCP Set)."

---

## Station Name Handling

The controller documentation already states: "RTU station_name comes from the
device itself via DCP discovery."

**Do NOT use DCP Set-Name.** The RTU generates its own name (`rtu-XXXX` from
MAC). The controller discovers it and uses it as-is.

The DCP Identify Response contains the station name in
DCP_OPTION_DEVICE / DCP_SUBOPTION_DEVICE_NAME. The controller parses this
at `dcp_discovery.py:175-180` and stores it as the RTU identifier.

**ACTION**: Same as the DHCP note above — remove DCP Set-Name from the
Water-Controller `CLAUDE.md` connection sequence. The controller reads the
station name from DCP Identify Response, it does not write one.

---

## Verification Checklist

After each phase, verify with a packet capture:

### Phase 0 verification
- [x] ARBlockReq block_length = 54 + station_name_len (no padding)
- [x] Wire bytes for block_length: `00 3E` for 8-char name
- [x] AlarmCRBlockReq tag_header_high = `C0 00`, tag_header_low = `A0 00`
- [x] NDR header present (20 bytes between RPC header and first block)
- [x] RPC `frag_len` matches actual payload (in LE)
- [x] RPC `if_version` = `01 00 00 00` (LE for value 1)
- [x] RPC `seqnum` increments by 1 in LE
- [x] Interface UUID NOT byte-swapped — p-net responds (not silence)
- [x] Strategy system retired — single correct wire format only
- [ ] No inter-block alignment padding — byte after each block is `0x01xx` block_type, not `0x00`

### Phase 1 verification
- [ ] RTU responds with FragLen > 20
- [ ] Response contains ARBlockRes (0x8101)
- [ ] Response contains IOCRBlockRes (0x8102)
- [ ] Response contains ModuleDiffBlock (0x8104)
- [ ] No PNIO error status in response

### Phase 2 verification
- [ ] ExpectedSubmoduleBlockReq lists all configured modules
- [ ] IOCRBlockReq data_length accounts for all submodule data sizes
- [ ] ModuleDiffBlock shows MODULE_STATE_PROPER for plugged modules
- [ ] Cyclic data exchange starts after ApplicationReady
