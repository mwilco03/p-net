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

## Reference Implementations

Open-source codebases that implement PROFINET controller or device connectivity:

| Repo | Language | What it does | Link |
|------|----------|-------------|------|
| secdev/scapy `pnio_rpc.py` | Python | Full block definitions for every PNIO block type. Most complete wire-format reference. | [source](https://github.com/secdev/scapy/blob/master/scapy/contrib/pnio_rpc.py) |
| secdev/scapy `pnio_rpc.uts` | Python | Test suite with a complete Connect request built from blocks | [tests](https://github.com/secdev/scapy/blob/master/test/contrib/pnio_rpc.uts) |
| alfredkrohmer/profinet | Python | Sends Connect with ARBlockReq. Shows Object UUID construction from vendor/device ID. | [source](https://github.com/alfredkrohmer/profinet) |
| Wireshark `packet-dcerpc-pn-io.c` | C | Dissector with full block type table, UUID constants, validation logic. | [source](https://github.com/boundary/wireshark/blob/master/plugins/profinet/packet-dcerpc-pn-io.c) |
| DCE 1.1 RPC Spec, Chapter 12 | Spec | Connectionless PDU header format, UUID encoding rules per DREP. | [spec](https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm) |

---

## p-net Vendor ID / Device ID Review

### How vendor_id is set in p-net code

The RTU application passes vendor_id and device_id to p-net once at startup
via the `pnet_cfg_t` struct (`include/pnet_api.h:1230-1236`):

```c
typedef struct pnet_cfg_device_id {
   uint8_t vendor_id_hi;
   uint8_t vendor_id_lo;
   uint8_t device_id_hi;
   uint8_t device_id_lo;
} pnet_cfg_device_id_t;
```

The struct is a member of `pnet_cfg_t` (`include/pnet_api.h:1370-1371`):
```c
pnet_cfg_device_id_t device_id;
pnet_cfg_device_id_t oem_device_id;
```

At init, `pf_cmina_init()` copies it into the DCP ASE (`pf_cmina.c:194`):
```c
net->cmina_nonvolatile_dcp_ase.device_id = p_cfg->device_id;
```

From that point forward, the values live at two locations:
- `net->fspm_cfg.device_id` — the original config, never modified
- `net->cmina_current_dcp_ase.device_id` — the active DCP copy

**The RTU (`rtu-4b64`) reports these values via DCP Identify Response**
(from `new.txt` lines 103-109):
```
VendorID: 0x0493
DeviceID: 0x0001
```

So the Water-treat application calls `pnet_init()` with:
```c
cfg.device_id.vendor_id_hi = 0x04;
cfg.device_id.vendor_id_lo = 0x93;
cfg.device_id.device_id_hi = 0x00;
cfg.device_id.device_id_lo = 0x01;
```

p-net's test suite uses different sample values
(`test/utils_for_testing.cpp:484-491`):
```c
pnet_default_cfg.device_id.vendor_id_hi = 0xfe;  /* 0xFEED */
pnet_default_cfg.device_id.vendor_id_lo = 0xed;
pnet_default_cfg.device_id.device_id_hi = 0xbe;  /* 0xBEEF */
pnet_default_cfg.device_id.device_id_lo = 0xef;
```

These are test-only values — the test suite also sets station_name to `""`,
product_name to `"PNET unit tests"`, and IP to `192.168.1.171`. The full
test config is at `test/utils_for_testing.cpp:464-539`.

### Where vendor_id/device_id are used in p-net

Three places, all outbound (p-net sends these values TO the controller,
never checks them FROM the controller):

| Location | Direction | What it does |
|----------|-----------|-------------|
| `pf_cmina.c:194` | Outbound | Copies from config into DCP ASE. Returned in DCP Identify and DCP Get responses (option 0x02, suboption 0x03) at `pf_cmina.c:1156`. |
| `pf_cmrpc_epm.c:228-236` | Outbound | Fills the last 6 bytes (node field) of the Object UUID in EPM Lookup Response. Format: `DEA00000-6C97-11D1-8271-{instance 00 01}{device_id}{vendor_id}`. |
| `pf_block_writer.c:2326-2327` | Outbound | Writes `im_vendor_id_hi/lo` into I&M0 (Identification & Maintenance) record data. This is the IM_0 data, separate from the device_id config. |

### Where vendor_id/device_id are NOT used

**The connect request validation chain does NOT check vendor_id or device_id
from the incoming packet against the device's own configured values.**

`pf_cmdev_check_ar_param()` at `pf_cmdev.c:1674-1814` validates these
fields in order (see Test Cases below for details):

1. ar_type (must be IOCAR_SINGLE)
2. ar_uuid (must be non-zero)
3. mac (must not be multicast)
4. CMInitiatorObjectUUID (prefix only — see below)
5. ar_properties.state (must be Active)
6. parameterization_server (must not be External)
7. companion_ar (must not be 3)
8. activity_timeout_factor (1-1000)
9. station_name length and visible chars

None of these compare anything against `net->fspm_cfg.device_id`.

The CMInitiatorObjectUUID check (`pf_cmdev.c:1602-1615`) validates only the
first 10 bytes: `data1 == 0xDEA00000`, `data2 == 0x6C97`, `data3 == 0x11D1`,
`data4[0] == 0x82`, `data4[1] == 0x71`. The last 6 bytes (instance,
device_id, vendor_id encoded in the UUID node field) are **not checked**.
Any values pass.

The RPC header Object UUID (offset 8-23) is not validated for Connect
requests at all. p-net only checks the Interface UUID for routing at
`pf_cmrpc.c:4690-4694`.

**Nothing in p-net prevents sample vendor_id `0xFEED` / device_id `0xBEEF`
or production values `0x0493` / `0x0001` from connecting.** These values
are only sent outbound in DCP, EPM, and I&M responses — never validated
on inbound Connect requests.

---

## Test Cases

Each test case is a verifiable check against the reference implementations.
For each one: review the Water-Controller code, compare against the reference,
and verify on wire with a pcap.

### Test 1: CMInitiatorObjectUUID prefix

The `CMInitiatorObjectUUID` field inside ARBlockReq (16 bytes at offset 132
of the connect request) must have the PROFINET Object UUID prefix.

**p-net code** (`pf_cmdev.c:1602-1615`):
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

Fails with error code 8 (`FAULTY_AR_BLOCK_REQ`) at `pf_cmdev.c:1714-1724`.

**Scapy reference** (`pnio_rpc.uts` line 596):
```python
CMInitiatorObjectUUID='dea00000-6c97-11d1-8271-010203040506'
```

**alfredkrohmer/profinet reference** (`rpc.py`):
```python
OBJECT_UUID_PREFIX = bytes([0xDE,0xA0,0x00,0x00,0x6C,0x97,0x11,0xD1,0x82,0x71])
object_uuid = OBJECT_UUID_PREFIX + bytes([0x00, 0x01,
    self.info.devHigh, self.info.devLow,
    self.info.vendorHigh, self.info.vendorLow])
```

Last 6 bytes encode: instance (2 bytes BE) + device_id (2 bytes BE) +
vendor_id (2 bytes BE). p-net does not validate these bytes — any values pass.

**Verify**: In pcap, bytes at offset 132-141 of the connect request (after
RPC header + NDR) must be `DE A0 00 00 6C 97 11 D1 82 71`. Bytes 142-147
are free (instance/device/vendor of the controller).

---

### Test 2: RPC header Object UUID prefix

The Object UUID in the RPC header (offset 8-23, 16 bytes) uses the same
`DEA00000` prefix. p-net does not validate this field for Connect — only the
Interface UUID is checked at `pf_cmrpc.c:4690` — but every reference
implementation uses this format.

**Scapy reference** (`pnio_rpc.uts` line 594):
```python
DceRpc4(
  object='dea00000-6c97-11d1-8271-010203040506',
  ...
)
```

**alfredkrohmer/profinet** (`rpc.py`):
```python
object_uuid = OBJECT_UUID_PREFIX + bytes([0x00, 0x01,
    self.info.devHigh, self.info.devLow,
    self.info.vendorHigh, self.info.vendorLow])
```

p-net's own EPM response builder uses this format (`pf_cmrpc_epm.c:218-236`):
```c
memcpy(&p_lookup_rsp->rpc_entry.object_uuid,
       &uuid_io_object_instance, ...);  /* DEA00000-6C97-11D1-8271-... */
p_lookup_rsp->rpc_entry.object_uuid.node[0] = 0x00;
p_lookup_rsp->rpc_entry.object_uuid.node[1] = 0x01;
p_lookup_rsp->rpc_entry.object_uuid.node[2] = net->fspm_cfg.device_id.device_id_hi;
p_lookup_rsp->rpc_entry.object_uuid.node[3] = net->fspm_cfg.device_id.device_id_lo;
p_lookup_rsp->rpc_entry.object_uuid.node[4] = net->fspm_cfg.device_id.vendor_id_hi;
p_lookup_rsp->rpc_entry.object_uuid.node[5] = net->fspm_cfg.device_id.vendor_id_lo;
```

With DREP=0x10 (LE), data1/data2/data3 are byte-swapped on wire.

**Verify**: At pcap offset 8, first 4 bytes should be `00 00 A0 DE` (data1
`0xDEA00000` in LE), then `97 6C` (data2 LE), then `D1 11` (data3 LE),
then `82 71` (data4, always BE).

---

### Test 3: ARProperties bit field

ARProperties is a uint32 BE at offset 148 of the connect request.

**p-net checks** (`pf_cmdev.c:1726-1768`):
- Bits 0-2 (`state`) must be 1 (Active) — error code 9
- Bit 4 (`parameterization_server`) must be 1 (CM_Initiator) — error code 9
- Bits 10-9 (`companion_ar`) must not be 3 — error code 9

**Scapy reference** (`pnio_rpc.py:776-817`):
```python
class ARBlockReq(Block):
    fields_desc = [
        ...
        BitField("ARProperties_PullModuleAlarmAllowed", 0, 1),    # bit 31
        BitEnumField("ARProperties_StartupMode", 0, 1, ...),      # bit 30
        BitField("ARProperties_reserved_3", 0, 6),                 # bits 29-24
        BitField("ARProperties_reserved_2", 0, 12),                # bits 23-12
        BitField("ARProperties_AcknowledgeCompanionAR", 0, 1),    # bit 11
        BitEnumField("ARProperties_CompanionAR", 0, 2, ...),      # bits 10-9
        BitEnumField("ARProperties_DeviceAccess", 0, 1, ...),     # bit 8
        BitField("ARProperties_reserved_1", 0, 3),                 # bits 7-5
        BitEnumField("ARProperties_ParametrizationServer", 0, 1,...), # bit 4
        BitField("ARProperties_SupervisorTakeoverAllowed", 0, 1), # bit 3
        BitEnumField("ARProperties_State", 1, 3, {1: "Active"}),  # bits 2-0
    ]
```

Minimum correct value: `0x00000011` (bit 4 = 1, bits 0-2 = 1).

**Verify**: At pcap offset 148, bytes should be `00 00 00 11` (or with
StartupMode bit 30 set: `40 00 00 11`).

---

### Test 4: AlarmCRBlockReq VLAN priority tags

**p-net check** (`pf_cmdev.c:4088-4098`):
```c
if (p_ar->alarm_cr_request.alarm_cr_tag_header_high.alarm_user_priority != 6)
   /* error code 11 */
```

**Scapy reference** (`pnio_rpc.py:1133-1169`):
```python
class AlarmCRBlockReq(Block):
    fields_desc = [
        ...
        ShortField("AlarmCRTagHeaderHigh", 0xC000),  # VLAN prio 6
        ShortField("AlarmCRTagHeaderLow", 0xA000),   # VLAN prio 5
    ]
```

**Verify**: In AlarmCRBlockReq, last 4 bytes must be `C0 00 A0 00`.

---

### Test 5: block_length calculation

`block_length = total_block_bytes - 4`. Excludes block_type (2) and
block_length (2). Includes version_high (1) + version_low (1) + data.

**Scapy reference** (`pnio_rpc.py:347-352`):
```python
def post_build(self, p, pay):
    if self.block_length is None:
        length = len(p) - 4  # block_type and block_length excluded
        p = p[:2] + struct.pack("!H", length) + p[4:]
```

**p-net validation** (`pf_cmrpc.c:1176`):
```c
if (p_block_header->block_length != block_length)  /* reject */
```

Expected values:

| Block | block_length |
|-------|-------------|
| ARBlockReq | `54 + strlen(station_name)` |
| AlarmCRBlockReq | 22 (`0x0016`) |
| IOCRBlockReq | dynamic |
| ExpectedSubmoduleBlockReq | dynamic |

**Verify**: For station name "rtu-4b64" (8 chars), ARBlockReq block_length
bytes at offset 102-103 must be `00 3E` (62).

---

### Test 6: NDR wrapper endianness

The 20-byte NDR header between RPC header and PNIO blocks uses DREP
endianness (LE with DREP=0x10), NOT big-endian.

**p-net code** (`pf_block_reader.c:836-865`): Parses NDR fields using
the RPC header's `is_big_endian` flag, which is `false` for DREP=0x10.

**p-net validation** (`pf_block_reader.c:848-854`):
```c
if (p_ndr->args_maximum < p_ndr->args_length ||
    p_ndr->args_maximum < p_ndr->array.maximum_count ||
    p_ndr->array.maximum_count < p_ndr->args_length ||
    p_ndr->args_length != p_ndr->array.actual_count)
```

**Scapy reference** (`pnio_rpc.py:1469-1521`):
```python
class PNIOServiceReqPDU(Packet):
    fields_desc = [
        EField(
            FieldLenField("args_max", None, fmt="I", length_of="blocks"),
            endianness_from=dce_rpc_endianness),  # follows DREP
        NDRData,  # args_length, max_count, offset, actual_count — all per DREP
    ]
```

Layout (all uint32, LE):
```
Offset  Field          Value
80      args_max       >= args_length
84      args_length    total PNIO block bytes
88      max_count      >= args_length
92      offset         0
96      actual_count   == args_length
```

**Verify**: If total block payload is e.g. 273 bytes (`0x111`), offset 84
must be `11 01 00 00` (LE), NOT `00 00 01 11` (BE).

---

### Test 7: Block ordering

ARBlockReq must be the first PNIO block. p-net enforces this at
`pf_cmrpc.c:1247-1257`. Remaining blocks can be in any order.

**Scapy test** (`pnio_rpc.uts` lines 592-680):
```python
PNIOServiceReqPDU(blocks=[
    ARBlockReq(...),           # first
    IOCRBlockReq(InputCR),     # then IOCR
    IOCRBlockReq(OutputCR),
    ExpectedSubmoduleBlockReq(...),
    # AlarmCRBlockReq(...)     # (omitted in test, required by p-net)
])
```

p-net requires (`pf_cmdev.c:4227-4250`):
- At least 1 Input IOCR and 1 Output IOCR (unless `device_access=true`)
- Exactly 1 AlarmCR (unless `device_access=true`)

**Verify**: First block_type after NDR must be `01 01` (ARBlockReq).

---

### Test 8: Blocks are concatenated with no inter-block padding

**Scapy test hex** (`pnio_rpc.uts` lines 683-697) — blocks immediately
follow each other:
```
...706c632d31 0102003e...
              ^^^^^^^^
   "plc-1" ends, IOCRBlockReq starts immediately (0x0102)
```

**p-net parser** (`pf_cmrpc.c:1231-1704`) — reads next block_header
immediately after each block handler returns. No padding skip.

**p-net response writer** (`pf_cmrpc.c:1840-1855`) — writes ARBlockRes
then IOCRBlockRes back-to-back with no padding between them.

**Verify**: In pcap hex dump, byte after each block's content (at
`block_start + 4 + block_length`) is the high byte of the next block_type
(`0x01` for request blocks).

---

### Test 9: Interface UUID not swapped

Interface UUID constants are stored as big-endian byte arrays. With
DREP=0x10 (LE), they go on wire WITHOUT `uuid_swap_fields()`.

**p-net check** (`pf_cmrpc.c:4690-4694`):
```c
memcmp(&rpc_req.interface_uuid, &uuid_io_device_interface,
       sizeof(rpc_req.object_uuid))
```

Where `uuid_io_device_interface = {0xDEA00001, 0x6C97, 0x11D1, ...}`
(`pf_cmrpc.c:83-87`).

**alfredkrohmer/profinet** uses BE DREP (0x00) — no swap needed at all:
```python
IFACE_UUID_DEVICE = uuid.UUID('{dea00001-6c97-11d1-8271-00a02442df7d}')
```

The Interface UUID byte arrays `PNIO_DEVICE_INTERFACE_UUID` are already in
the form that `uuid_swap_fields()` would produce. Swapping them double-swaps.

**Verify**: At pcap offset 24, bytes must be
`01 00 A0 DE 97 6C D1 11 82 71 00 A0 24 42 DF 7D` (LE encoding of
`DEA00001-6C97-11D1-8271-00A02442DF7D`). If you see
`DE A0 00 01 6C 97 11 D1 ...` that is BE / double-swapped — will be
silently dropped.

---

### Test 10: Activity timeout factor range

**p-net check** (`pf_cmdev.c:1770-1781`):
```c
if ((p_ar->ar_param.cm_initiator_activity_timeout_factor < 1) ||
    (p_ar->ar_param.cm_initiator_activity_timeout_factor > 1000))
```

Fails with error code 10. Valid range: 1-1000 (resolution: 100ms, so
1000 = 100 seconds).

**Scapy default** (`pnio_rpc.py:812`):
```python
ShortField("CMInitiatorActivityTimeoutFactor", 1000),
```

**Verify**: At offset 152, bytes should be between `00 01` and `03 E8` (BE).

---

### Test 11: Station name non-empty and visible ASCII

**p-net checks** (`pf_cmdev.c:1783-1807`):
- Length must be > 0 and < `PNET_STATION_NAME_MAX_SIZE` — error code 12
- All chars must be visible ASCII (0x20-0x7E) — error code 13

**Verify**: Station name bytes in ARBlockReq must be non-empty printable
ASCII matching the device's DCP-discovered name.

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
