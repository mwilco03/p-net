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

**Fix**: Calculate block_length BEFORE alignment padding:
```c
469    size_t name_len = strlen(params->station_name);
470    write_u16_be(buffer, (uint16_t)name_len, &pos);
471    memcpy(buffer + pos, params->station_name, name_len);
472    pos += name_len;
473
474    /* Fill AR block header BEFORE adding inter-block padding */
475    size_t ar_block_len = pos - ar_block_start - 4;
476    size_t save_pos = ar_block_start;
477    write_block_header(buffer, BLOCK_TYPE_AR_BLOCK_REQ,
478                        (uint16_t)ar_block_len, &save_pos);
479
480    /* NOW align for next block */
481    align_to_4(&pos);
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

**Fix**: After fixing Bug 0.1 (block_length before alignment), also zero the
padding bytes:
```c
    pos += name_len;

    /* Calculate block_length before padding */
    size_t ar_block_len = pos - ar_block_start - 4;
    /* ... write block header ... */

    /* Zero-fill alignment padding */
    while (pos % 4 != 0) {
        buffer[pos++] = 0;
    }
```

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

### Phase 0 Completion Summary

All six controller-side bugs have been identified and fixed. Seven additional
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

## Reference Implementation Guide

This section provides field-by-field wire format details derived from analyzing
every open-source PROFINET controller implementation available. Code references
to both p-net (device side, this repo) and public implementations are included.

**Reference codebases reviewed:**

| Repo | Language | What it implements |
|------|----------|--------------------|
| [secdev/scapy `pnio_rpc.py`](https://github.com/secdev/scapy/blob/master/scapy/contrib/pnio_rpc.py) | Python | Full block definitions for every PNIO block type. Most complete wire-format reference. |
| [alfredkrohmer/profinet](https://github.com/alfredkrohmer/profinet) | Python | Sends ARBlockReq-only Connect. Shows Object UUID construction from vendor/device ID. |
| [Wireshark `packet-dcerpc-pn-io.c`](https://github.com/boundary/wireshark/blob/master/plugins/profinet/packet-dcerpc-pn-io.c) | C | Dissector with full block type table, UUID constants, validation checks. |
| [DCE 1.1 RPC Spec, Chapter 12](https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm) | Spec | Connectionless PDU header format, UUID encoding rules per DREP. |

---

### Critical: CMInitiatorObjectUUID Format

p-net **rejects** the Connect request if the `CMInitiatorObjectUUID` inside the
ARBlockReq does not match the PROFINET Object UUID prefix.

**p-net validation** (`pf_cmdev.c:1602-1615`):
```c
static int pf_cmdev_check_cm_initiator_object_uuid (const pf_uuid_t * p_uuid)
{
   int ret = -1;
   if (
      (p_uuid->data1 == 0xDEA00000) && (p_uuid->data2 == 0x6c97) &&
      (p_uuid->data3 == 0x11D1) && (p_uuid->data4[0] == 0x82) &&
      (p_uuid->data4[1] == 0x71))
   {
      ret = 0;
   }
   return ret;
}
```

If this check fails, p-net returns error code 8 (`FAULTY_AR_BLOCK_REQ`)
at `pf_cmdev.c:1714-1724`.

**What Water-Controller currently does** (`ar_manager.c` / `profinet_rpc.c`):
```c
/* ar_manager_init() — generates random UUID4 once */
rpc_generate_uuid(mgr->controller_uuid);

/* rpc_build_connect_request() — writes it as CMInitiatorObjectUUID */
memcpy(buffer + pos, params->controller_uuid, 16);  pos += 16;
```

`rpc_generate_uuid()` produces `XXXXXXXX-XXXX-4XXX-8XXX-XXXXXXXXXXXX` —
a random UUID4 where `data1 != 0xDEA00000`. p-net rejects this.

**Required format** (from Scapy `pnio_rpc.py` and alfredkrohmer `rpc.py`):
```
DEA00000-6C97-11D1-8271-{instance_hi}{instance_lo}{device_hi}{device_lo}{vendor_hi}{vendor_lo}
```

The last 6 bytes of the UUID encode the **controller's** identity:

| Bytes | Field | Size | Source |
|-------|-------|------|--------|
| 10-11 | Instance number | uint16 BE | Controller instance (typically 0x0001) |
| 12-13 | Device ID | uint16 BE | Controller's own device ID |
| 14-15 | Vendor ID | uint16 BE | Controller's own vendor ID |

**Fix** — replace `rpc_generate_uuid()` for `controller_uuid` with:
```c
/* Water-Controller: profinet_rpc.c or ar_manager.c */
static void build_controller_object_uuid(uint8_t *uuid,
                                          uint16_t instance,
                                          uint16_t device_id,
                                          uint16_t vendor_id)
{
    /* Fixed PROFINET Object UUID prefix (10 bytes) */
    static const uint8_t prefix[10] = {
        0xDE, 0xA0, 0x00, 0x00,  /* data1: DEA00000 */
        0x6C, 0x97,              /* data2: 6C97 */
        0x11, 0xD1,              /* data3: 11D1 */
        0x82, 0x71               /* data4[0..1] */
    };
    memcpy(uuid, prefix, 10);
    uuid[10] = (uint8_t)(instance >> 8);
    uuid[11] = (uint8_t)(instance & 0xFF);
    uuid[12] = (uint8_t)(device_id >> 8);
    uuid[13] = (uint8_t)(device_id & 0xFF);
    uuid[14] = (uint8_t)(vendor_id >> 8);
    uuid[15] = (uint8_t)(vendor_id & 0xFF);
}

/* In ar_manager_init(): */
build_controller_object_uuid(mgr->controller_uuid,
    0x0001,           /* instance */
    CONTROLLER_DEVICE_ID,
    CONTROLLER_VENDOR_ID);
```

**alfredkrohmer/profinet reference** (`rpc.py`):
```python
OBJECT_UUID_PREFIX = bytes([0xDE,0xA0,0x00,0x00,0x6C,0x97,0x11,0xD1,0x82,0x71])
# Last 6 bytes: instance(2) + device_id(2) + vendor_id(2)
object_uuid = OBJECT_UUID_PREFIX + bytes([0x00, 0x01,
    self.info.devHigh, self.info.devLow,
    self.info.vendorHigh, self.info.vendorLow])
```

**Scapy reference** (`pnio_rpc.py` test, line 596):
```python
CMInitiatorObjectUUID='dea00000-6c97-11d1-8271-010203040506'
```

**NOTE**: The RPC header's Object UUID (offset 8-23 in the 80-byte header)
should ALSO use this same `DEA00000` prefix format. p-net does not validate
the RPC header Object UUID for Connect requests (only the Interface UUID
is checked for routing at `pf_cmrpc.c:4690`), but standard practice is to
set both to the same value.

---

### p-net AR Param Validation Chain

After the Interface UUID matches and the ARBlockReq is parsed, p-net validates
every field in sequence at `pf_cmdev_check_ar_param()` (`pf_cmdev.c:1674-1800`).
A failure at any step returns a Connect Response with the error code shown.
The controller MUST pass all of these:

| Order | Check | Error Code | p-net Location | What Water-Controller must send |
|-------|-------|------------|----------------|-------------------------------|
| 1 | `ar_type == IOCAR_SINGLE (1)` | ARBlockReq/4 | `pf_cmdev.c:1678` | `write_u16_be(buffer, 0x0001, &pos)` |
| 2 | `ar_uuid != all-zeros` | ARBlockReq/5 | `pf_cmdev.c:1689` | Any non-zero UUID (random is fine) |
| 3 | `mac_addr bit 0 == 0` (not multicast) | ARBlockReq/7 | `pf_cmdev.c:1703` | Controller's real unicast MAC |
| 4 | `cm_initiator_object_uuid` prefix = `DEA00000-6C97-11D1-8271-` | ARBlockReq/8 | `pf_cmdev.c:1714` | See fix above |
| 5 | `ar_properties.state == ACTIVE (1)` | ARBlockReq/9 | `pf_cmdev.c:1726` | Set bits 0-2 of ARProperties = 0x1 |
| 6 | `parameterization_server != EXTERNAL` | ARBlockReq/10 | `pf_cmdev.c:1737` | Set bit 4 of ARProperties = 1 (CM_Initiator) |
| 7 | `station_name` matches device's own name | ARBlockReq/14 | `pf_cmdev.c:1791` | Must equal DCP-discovered name |

**ARProperties** is a uint32 (big-endian in block body). The required value
for a standard IOCAR_SINGLE with CM_Initiator parameterization:

```
Bit layout (MSB to LSB):
  [31]    PullModuleAlarmAllowed = 0
  [30]    StartupMode            = 0 (Legacy) or 1 (Advanced)
  [29:24] Reserved               = 0
  [23:12] Reserved               = 0
  [11]    AcknowledgeCompanionAR = 0
  [10:9]  CompanionAR            = 0 (Single_AR)
  [8]     DeviceAccess           = 0 (ExpectedSubmodule)
  [7:5]   Reserved               = 0
  [4]     ParametrizationServer  = 1 (CM_Initiator)  ← REQUIRED
  [3]     SupervisorTakeoverAllowed = 0
  [2:0]   State                  = 1 (Active)         ← REQUIRED

Minimum correct value: 0x00000011  (CM_Initiator + Active)
```

**Scapy reference** (`pnio_rpc.py:776-817`): ARBlockReq fields_desc shows exact
bit layout. Default `ARProperties_State=1`, `ARProperties_ParametrizationServer`
must be set to `"CM_Initator"` (1).

---

### Two Endianness Layers

The connect request has two byte-ordering domains. Getting these wrong causes
either silent drop (RPC header) or block parse errors (PNIO blocks).

**Layer 1: RPC header (80 bytes) — endianness per DREP**

DREP `0x10` = little-endian. All multi-byte integer fields in the header
(`server_boot`, `interface_version`, `sequence_number`, `opnum`,
`fragment_length`, etc.) are LE. UUID fields `data1`/`data2`/`data3` are
LE; `data4` (8 bytes) is always BE (byte array, not integer).

Water-Controller uses direct struct assignment on an LE platform, which is
correct. The `_Static_assert` at compile time enforces this (Bug 0.3).

**Layer 2: PNIO block content — ALWAYS big-endian**

After the NDR header, p-net switches to big-endian parsing at
`pf_cmrpc.c:4636`:
```c
/* From now on all is big-endian */
p_sess->get_info.is_big_endian = true;
```

All block headers (`block_type`, `block_length`, `version`) and all fields
inside ARBlockReq, IOCRBlockReq, ExpectedSubmoduleBlockReq, AlarmCRBlockReq
are big-endian. Water-Controller uses `write_u16_be()` and `write_u32_be()`
for these, which is correct.

**Layer 1.5: NDR wrapper (20 bytes) — endianness per DREP**

The 5x uint32 NDR fields are encoded per DREP (LE with DREP=0x10), NOT
big-endian. p-net parses them at `pf_block_reader.c:836-865` using the
RPC header's `is_big_endian` flag (which is false for DREP=0x10).

Water-Controller's `write_ndr_request_header()` must write these as LE.
If it currently uses `write_u32_be()` for NDR, that is wrong.

**Summary of endianness per section:**

| Section | Offset | Endianness | Water-Controller function |
|---------|--------|------------|--------------------------|
| RPC header | 0-79 | LE (per DREP=0x10) | Direct struct assignment (LE platform) |
| NDR wrapper | 80-99 | LE (per DREP=0x10) | Must use LE writes |
| PNIO blocks | 100+ | Always BE | `write_u16_be()`, `write_u32_be()` |

---

### UUID Wire Encoding Per DREP

In the RPC header (Layer 1), UUIDs have mixed encoding per DCE 1.1 spec:

```
UUID struct:
  data1  (uint32)  → LE with DREP=0x10
  data2  (uint16)  → LE with DREP=0x10
  data3  (uint16)  → LE with DREP=0x10
  data4  (8 bytes) → always big-endian (byte array)
```

**Example: Interface UUID `DEA00001-6C97-11D1-8271-00A02442DF7D`**

```
LE wire bytes:  01 00 A0 DE  97 6C  D1 11  82 71 00 A0 24 42 DF 7D
                ^^^^^^^^^^^  ^^^^^  ^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^
                data1 (LE)   d2(LE) d3(LE) data4 (always BE)
```

p-net's parser (`pf_block_reader.c:150-158`) reads these back with
DREP-aware `pf_get_uint32()`/`pf_get_uint16()`, reconstructing
`{0xDEA00001, 0x6C97, 0x11D1, ...}` in host order.

Water-Controller's `uuid_swap_fields()` (`rpc_strategy.c`) correctly swaps
data1/data2/data3 byte order for LE wire encoding. The rule:
- **Object UUID**: swap (session-specific, generated in host order)
- **Activity UUID**: swap (session-specific, generated in host order)
- **Interface UUID**: do NOT swap (Bug 0.6 — constants are stored as
  big-endian byte arrays, not host-order integers)

---

### No Inter-Block Padding

Blocks are concatenated directly with zero padding between them.

**Scapy evidence** (`pnio_rpc.py` test hex, lines 683-697):
```
...706c632d31  0102003e...
   ^^^^^^^^^^  ^^^^^^^^
   end of ARBlockReq    start of IOCRBlockReq (no gap)
   "plc-1"             block_type=0x0102
```

**p-net evidence** — the block parsing loop at `pf_cmrpc.c:1231-1704`
reads the next `pf_get_block_header()` immediately after each block
handler finishes. No alignment skip between iterations.

**p-net's own response writer** (`pf_cmrpc.c:1840-1855`) writes
ARBlockRes then IOCRBlockRes back-to-back with no padding.

Water-Controller's `align_to_4(&pos)` between blocks writes zero-fill
padding. This does NOT prevent connections — p-net tolerates it for some
block boundaries. But for clean wire format, consider removing it.
The `align_to_4()` WITHIN blocks (before block_length calculation) is
handled by Bug 0.1/0.5 fixes.

---

### block_length Formula

```
block_length = total_block_bytes - 4
```

The 4 excluded bytes are `block_type` (2) + `block_length` (2).
Everything from `block_version_high` onward is counted.

**Scapy** (`pnio_rpc.py:347-352`):
```python
def post_build(self, p, pay):
    if self.block_length is None:
        length = len(p) - 4  # block_type and block_length excluded
        p = p[:2] + struct.pack("!H", length) + p[4:]
```

**p-net validation** (`pf_cmrpc.c:1176`):
```c
if (p_block_header->block_length != block_length)  /* Reject mismatch */
```

**Expected values per block type:**

| Block | block_length | Calculation |
|-------|-------------|-------------|
| ARBlockReq | `54 + strlen(station_name)` | 2 (version) + 52 (fixed) + N (name) |
| IOCRBlockReq | Dynamic | 2 (version) + 42 (fixed) + APIs |
| AlarmCRBlockReq | 22 (0x0016) | 2 (version) + 20 (fixed fields) |
| ExpectedSubmoduleBlockReq | Dynamic | 2 (version) + 2 (num_apis) + APIs |

---

### NDR Wrapper Format (20 bytes)

Between the RPC header and the first PNIO block. All uint32, LE per DREP.

```
Offset  Size  Field          Value
0       4     args_max       Max response buffer size (e.g., 1384)
4       4     args_length    Total PNIO block bytes that follow
8       4     max_count      = args_length
12      4     offset         0
16      4     actual_count   = args_length
```

**p-net validation** (`pf_block_reader.c:848-854`):
```c
if (p_ndr->args_maximum < p_ndr->args_length ||
    p_ndr->args_maximum < p_ndr->array.maximum_count ||
    p_ndr->array.maximum_count < p_ndr->args_length ||
    p_ndr->args_length != p_ndr->array.actual_count)
{
   ret = -1;  /* "Invalid NDR header" */
}
```

Rules: `args_max >= args_length`, `max_count >= args_length`,
`actual_count == args_length`, `offset == 0`.

---

### Complete Connect Request Wire Layout

Byte-by-byte layout of a minimal Connect request (reference from Scapy test):

```
Offset  Size  Field
────────────────────────────── RPC Header (80 bytes, LE per DREP) ──
0       1     rpc_version          = 0x04
1       1     packet_type          = 0x00 (Request)
2       1     flags1               = 0x20 (Idempotent)
3       1     flags2               = 0x00
4       1     drep[0]              = 0x10 (LE, ASCII)
5       1     drep[1]              = 0x00 (IEEE float)
6       1     drep[2]              = 0x00 (reserved)
7       1     serial_hi            = 0x00
8       16    object_uuid          = DEA00000 prefix, LE-swapped data1/2/3
24      16    interface_uuid       = DEA00001 prefix, NOT swapped (Bug 0.6)
40      16    activity_uuid        = random, LE-swapped data1/2/3
56      4     server_boot_time     = 0x00000000 (LE)
60      4     interface_version    = 0x01000000 (value 1, LE)
64      4     sequence_number      = increments (LE)
68      2     opnum                = 0x0000 (Connect, LE)
70      2     interface_hint       = 0xFFFF (LE)
72      2     activity_hint        = 0xFFFF (LE)
74      2     fragment_length      = total_after_header (LE)
76      2     fragment_number      = 0x0000
78      1     auth_protocol        = 0x00
79      1     serial_lo            = 0x00
────────────────────────────── NDR Wrapper (20 bytes, LE per DREP) ──
80      4     args_max             (LE)
84      4     args_length          = total block bytes (LE)
88      4     max_count            = args_length (LE)
92      4     offset               = 0x00000000
96      4     actual_count         = args_length (LE)
────────────────────────────── PNIO Blocks (all fields BE) ─────────
100     2     block_type           = 0x0101 (ARBlockReq)
102     2     block_length         = 54 + station_name_len
104     1     version_high         = 0x01
105     1     version_low          = 0x00
106     2     ar_type              = 0x0001 (IOCAR_SINGLE)
108     16    ar_uuid              = random non-zero UUID
124     2     session_key          = 0x0001 (increments per connect)
126     6     cm_initiator_mac     = controller's unicast MAC
132     16    cm_initiator_obj_uuid = DEA00000-6C97-11D1-8271-{inst}{dev}{vend}
148     4     ar_properties        = 0x00000011 (CM_Initiator + Active)
152     2     activity_timeout     = 0x03E8 (1000 = 100s)
154     2     udp_rt_port          = 0x8892
156     2     station_name_length  = N
158     N     station_name         = DCP-discovered name (e.g., "rtu-4b64")
────────────────────────────── IOCRBlockReq #1 (Input CR) ──────────
...     2     block_type           = 0x0102
        2     block_length         = dynamic
        1     version_high         = 0x01
        1     version_low          = 0x00
        2     iocr_type            = 0x0001 (Input)
        2     iocr_reference       = 0x0001
        2     lt                   = 0x8892
        4     iocr_properties      = 0x00000000 (RT_CLASS_1)
        2     data_length          = 40 (minimum) or calculated
        2     frame_id             = 0xC001 (RT_CLASS_1 range)
        2     send_clock_factor    = 32
        2     reduction_ratio      = 32
        2     phase                = 1
        2     sequence             = 0
        4     frame_send_offset    = 0xFFFFFFFF
        2     watchdog_factor      = 10
        2     data_hold_factor     = 10
        2     iocr_tag_header      = 0xC000 (VLAN prio 6)
        6     multicast_mac        = 00:00:00:00:00:00
        2     number_of_apis       = 1
        4     api                  = 0x00000000
        2     num_io_data_objects  = (per submodules)
        ...   io_data_objects      = slot, subslot, frame_offset (6 bytes each)
        2     num_iocs             = (per submodules)
        ...   iocs                 = slot, subslot, frame_offset (6 bytes each)
────────────────────────────── IOCRBlockReq #2 (Output CR) ─────────
...     same structure, iocr_type = 0x0002, frame_id = 0xFFFF
────────────────────────────── ExpectedSubmoduleBlockReq ───────────
...     2     block_type           = 0x0104
        2     block_length         = dynamic
        1     version_high         = 0x01
        1     version_low          = 0x00
        2     number_of_apis       = 1
        4     api                  = 0x00000000
        2     slot_number          = 0x0000 (slot 0 for DAP)
        4     module_ident_number  = 0x00000001 (DAP)
        2     module_properties    = 0x0000
        2     number_of_submodules = 3 (DAP + Interface + Port)
        ── per submodule: ──
        2     subslot_number       = 0x0001 / 0x8000 / 0x8001
        4     submodule_ident      = 0x00000001 / 0x00000100 / 0x00000200
        2     submodule_properties = 0x0000 (NO_IO for DAP submodules)
        1+    data_description     = per SubmoduleProperties_Type
────────────────────────────── AlarmCRBlockReq ─────────────────────
...     2     block_type           = 0x0103
        2     block_length         = 0x0016 (22)
        1     version_high         = 0x01
        1     version_low          = 0x00
        2     alarm_cr_type        = 0x0001
        2     lt                   = 0x8892
        4     alarm_cr_properties  = 0x00000000
        2     rta_timeout_factor   = 0x0001
        2     rta_retries          = 0x0003
        2     local_alarm_ref      = 0x0001
        2     max_alarm_data_len   = 0x00C8 (200)
        2     tag_header_high      = 0xC000 (VLAN prio 6)
        2     tag_header_low       = 0xA000 (VLAN prio 5)
```

---

### Files to Change in Water-Controller

| File | Change | Why |
|------|--------|-----|
| `src/profinet/profinet_rpc.c` or `ar_manager.c` | Replace `rpc_generate_uuid()` for `controller_uuid` with `DEA00000` prefix builder | p-net rejects random UUID4 at `pf_cmdev.c:1714` |
| `src/profinet/profinet_rpc.c` | Verify NDR wrapper uses LE writes (not BE) | NDR follows DREP, not block endianness |
| `src/profinet/profinet_rpc.c` | Verify ARProperties includes bits 0-2=1 (Active) and bit 4=1 (CM_Initiator) | p-net rejects at `pf_cmdev.c:1726` and `:1737` |
| `src/profinet/profinet_rpc.c` | Verify `session_key` is non-zero and increments | Standard practice, used by p-net for AR matching |
| `src/profinet/profinet_rpc.c` | Set RPC header Object UUID to same `DEA00000` format | Standard practice per Scapy/alfredkrohmer |

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
