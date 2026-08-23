##! IEC 60870-5-104 logging (#1764).
##!
##! Port 2404 is the only ICS port this deployment exposes that ICSNPP does not
##! parse, so until now it produced a conn.log row and nothing else. This turns
##! it into transaction detail, in the same shape as the other ICS logs.
##!
##! Deliberately two logs rather than one. The APDU log records every frame,
##! which for this protocol is mostly handshake -- and on a honeypot the
##! handshake IS the event, because scanners overwhelmingly send STARTDT and
##! leave. The ASDU log records the frames that actually asked the device to do
##! something, which are rare and disproportionately interesting.

module IEC104;

export {
    redef enum Log::ID += { LOG_APDU, LOG_ASDU };

    type APDUInfo: record {
        ts:          time    &log;
        uid:         string  &log;
        id:          conn_id &log;
        is_orig:     bool    &log;
        ## I, S or U. U is the control handshake, which is what a scanner sends.
        format:      string  &log;
        ## STARTDT_ACT / STARTDT_CON / TESTFR_ACT / ... for U-format frames.
        u_function:  string  &log &optional;
        length:      count   &log;
    };

    type ASDUInfo: record {
        ts:          time    &log;
        uid:         string  &log;
        id:          conn_id &log;
        is_orig:     bool    &log;
        ## IEC-104 type identification, e.g. 100 = interrogation command.
        type_id:     count   &log;
        ## Cause of transmission, e.g. 6 = activation.
        cot:         count   &log;
        ## Common address of ASDU -- which device the request was aimed at.
        asdu_addr:   count   &log;
        ## Number of information objects in the frame.
        num_objects: count   &log;
    };
}

event zeek_init() &priority=5 {
    Log::create_stream(IEC104::LOG_APDU, [$columns=APDUInfo, $path="iec104"]);
    Log::create_stream(IEC104::LOG_ASDU, [$columns=ASDUInfo, $path="iec104_asdu"]);
}

event iec104::apdu(c: connection, is_orig: bool, format: string,
                   u_function: string, length: count) {
    local rec = APDUInfo($ts=network_time(), $uid=c$uid, $id=c$id,
                         $is_orig=is_orig, $format=format, $length=length);
    # Only U-format frames carry a function; leaving it unset beats writing an
    # empty string that looks like a decoded value.
    if ( u_function != "" )
        rec$u_function = u_function;
    Log::write(IEC104::LOG_APDU, rec);
}

event iec104::asdu(c: connection, is_orig: bool, type_id: count, cot: count,
                   asdu_addr: count, num_objects: count) {
    Log::write(IEC104::LOG_ASDU,
               ASDUInfo($ts=network_time(), $uid=c$uid, $id=c$id,
                        $is_orig=is_orig, $type_id=type_id, $cot=cot,
                        $asdu_addr=asdu_addr, $num_objects=num_objects));
}
