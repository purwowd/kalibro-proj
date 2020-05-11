from optparse import OptionParser
from scapy.all import sniff, UDP

import ctypes
import json
import datetime
import io
import socket
import sqlite3

imsitracker = None


class tracker:
    imsistate = {}
    imsis = []
    tmsis = {}
    nb_IMSI = 0

    mcc = ""
    mnc = ""
    lac = ""
    cell = ""
    country = ""
    brand = ""
    operator = ""

    purgeTimer = 10

    show_all_tmsi = False
    mcc_codes = None
    sqlcon = None
    textfile = None

    output_function = None

    def __init__(self):
        self.load_mcc_codes()
        self.track_this_imsi("")
        self.output_function = self.output

    def set_output_fuction(self, new_output_function):
        self.output_function = new_output_function

    def track_this_imsi(self, imsi_to_track):
        self.imsi_to_track = imsi_to_track
        self.imsi_to_track_len = len(imsi_to_track)

    def str_tmsi(self, tmsi):
        if tmsi != "":
            new_tmsi = "0x"
            for a in tmsi:
                c = hex(a)
                if len(c) == 4:
                    new_tmsi += str(c[2]) + str(c[3])
                else:
                    new_tmsi += "0" + str(c[2])
            return new_tmsi
        else:
            return ""

    def decode_imsi(self, imsi):
        new_imsi = ""
        for a in imsi:
            c = hex(a)
            if len(c) == 4:
                new_imsi += str(c[3] + str(c[2]))
            else:
                new_imsi += str(c[2]) + "0"

        mcc = new_imsi[1:4]
        mnc = new_imsi[4:6]

        return new_imsi, mcc, mnc

    def str_imsi(self, imsi, packet=""):
        new_imsi, mcc, mnc = self.decode_imsi(imsi)
        country = ""
        brand = ""
        operator = ""

        if mcc in self.mcc_codes:
            if mnc in self.mcc_codes[mcc]:
                brand, operator, country, _ = self.mcc_codes[mcc][mnc]
                new_imsi = mcc + " " + mnc + " " + new_imsi[6:]
            elif mnc + new_imsi[6:7] in self.mcc_codes[mcc]:
                mnc += new_imsi[6:7]
                brand, operator, country, _ = self.mcc_codes[mcc][mnc]
                new_imsi = mcc + " " + mnc + " " + new_imsi[7:]
        else:
            country = "Unknown MCC {}".format(mcc)
            brand = "Unknown MNC {}".format(mnc)
            operator = "Unknown MNC {}".format(mnc)
            new_imsi = mcc + " " + mnc + " " + new_imsi[6:]

        try:
            return new_imsi, country, brand, operator
        except Exception:
            print("Error", packet, new_imsi, country, brand, operator)
        return "", "", "", ""

    def load_mcc_codes(self):
        with io.open('mcc-mnc/mcc_codes.json', 'r', encoding='utf8') as file:
            self.mcc_codes = json.load(file)

    def current_cell(self, mcc, mnc, lac, cell):
        brand = ""
        operator = ""
        country = ""
        if mcc in self.mcc_codes and mnc in self.mcc_codes[mcc]:
            brand, operator, country, _ = self.mcc_codes[mcc][mnc]
        else:
            country = "Unknown MCC {}".format(mcc)
            brand = "Unknown MNC {}".format(mnc)
            operator = "Unknown MNC {}".format(mnc)
        self.mcc = str(mcc)
        self.mnc = str(mnc)
        self.lac = str(lac)
        self.cell = str(cell)
        self.country = country
        self.brand = brand
        self.operator = operator

    def sqlite_file(self, filename):
        print("Saving to SQLite database in %s" % filename)
        self.sqlcon = sqlite3.connect(filename)
        self.sqlcon.execute("CREATE TABLE IF NOT EXISTS observations(stamp datetime, tmsi1 text, tmsi2 text, imsi text, imsicountry text, imsibrand text, imsioperator text, mcc integer, mnc integer, lac integer, cell integer);")

    def textfile(self, filename):
        txt = open(filename, "w")
        txt.write("[START]\n")
        txt.close()
        self.textfile = filename

    def output(self, cpt, tmsi1, tmsi2, imsi, imsicountry, imsibrand, imsioperator, mcc, mnc, lac, cell, now, packet=None):
        print("{:7s} ; {:10s} ; {:10s} ; {:17s} ; {:12s} ; {:10s} ; {:21s} ; {:4s} ; {:5s} ; {:6s} ; {:6s} ; {:s}".format(str(cpt), tmsi1, tmsi2, imsi, imsicountry, imsibrand, imsioperator, str(mcc), str(mnc), str(lac), str(cell), now.isoformat()))

    def pfields(self, cpt, tmsi1, tmsi2, imsi, mcc, mnc, lac, cell, packet=None):
        imsicountry = ""
        imsibrand = ""
        imsioperator = ""
        if imsi:
            imsi, imsicountry, imsibrand, imsioperator = self.str_imsi(imsi, packet)
        else:
            imsi = ""
        now = datetime.datetime.now()
        self.output_function(cpt, tmsi1, tmsi2, imsi, imsicountry, imsibrand, imsioperator, mcc, mnc, lac, cell, now, packet)
        if self.sqlcon:
            if tmsi1 == "":
                tmsi1 = None
            if tmsi2 == "":
                tmsi2 = None
            self.sqlcon.execute(u"INSERT INTO observations (stamp, tmsi1, tmsi2, imsi, imsicountry, imsibrand, imsioperator, mcc, mnc, lac, cell) " + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", (now, tmsi1, tmsi2, imsi, imsicountry, imsibrand, imsioperator, mcc, mnc, lac, cell))
            self.sqlcon.commit()

        if self.textfile:
            now = datetime.datetime.now()
            txt = open(self.textfile, 'a')
            txt.write(str(now) + ", " + tmsi1 + ", " + tmsi2 + ", " + imsi + ", " + imsicountry + ", " + imsibrand + ", " + imsioperator + ", " + mcc + ", " + mnc + ", " + lac + ", " + cell + "\n")
            txt.close()

    def header(self):
        print("{:7s} ; {:10s} ; {:10s} ; {:17s} ; {:12s} ; {:10s} ; {:21s} ; {:4s} ; {:5s} ; {:6s} ; {:6s} ; {:s}".format("Nb IMSI", "TMSI-1", "TMSI-2", "IMSI", "country", "brand", "operator", "MCC", "MNC", "LAC", "CellId", "Timestamp"))

    def register_imsi(self, arfcn, imsi1="", imsi2="", tmsi1="", tmsi2="", p=""):
        do_print = False
        n = ''
        tmsi1 = self.str_tmsi(tmsi1)
        tmsi2 = self.str_tmsi(tmsi2)
        if imsi1:
            self.imsi_seen(imsi1, arfcn)
        if imsi2:
            self.imsi_seen(imsi2, arfcn)
        if imsi1 and (not self.imsi_to_track or imsi1[:self.imsi_to_track_len] == self.imsi_to_track):
            if imsi1 not in self.imsis:
                do_print = True
                self.imsis.append(imsi1)
                self.nb_IMSI += 1
                n = self.nb_IMSI
            if self.tmsis and tmsi1 and (tmsi1 not in self.tmsis or self.tmsis[tmsi1] != imsi1):
                do_print = True
                self.tmsis[tmsi1] = imsi1
            if self.tmsis and tmsi2 and (tmsi2 not in self.tmsis or self.tmsis[tmsi2] != imsi1):
                do_print = True
                self.tmsis[tmsi2] = imsi1

        if imsi2 and (not self.imsi_to_track or imsi2[:self.imsi_to_track_len] == self.imsi_to_track):
            if imsi2 not in self.imsis:
                do_print = True
                self.imsis.append(imsi2)
                self.nb_IMSI += 1
                n = self.nb_IMSI
            if self.tmsis and tmsi1 and (tmsi1 not in self.tmsis or self.tmsis[tmsi1] != imsi2):
                do_print = True
                self.tmsis[tmsi1] = imsi2
            if self.tmsis and tmsi2 and (tmsi2 not in self.tmsis or self.tmsis[tmsi2] != imsi2):
                do_print = True
                self.tmsis[tmsi2] = imsi2

        if not imsi1 and not imsi2 and tmsi1 and tmsi2:
            if self.tmsis and tmsi2 in self.tmsis:
                do_print = True
                imsi1 = self.tmsis[tmsi2]
                self.tmsis[tmsi1] = imsi1
                del self.tmsis[tmsi2]

        if do_print:
            if imsi1:
                self.pfields(str(n), tmsi1, tmsi2, imsi1, str(self.mcc), str(self.mnc), str(self.lac), str(self.cell), p)
            if imsi2:
                self.pfields(str(n), tmsi1, tmsi2, imsi2, str(self.mcc), str(self.mnc), str(self.lac), str(self.cell), p)

        if not imsi1 and not imsi2:
            if self.tmsis and tmsi1 and tmsi1 in self.tmsis and "" != self.tmsis[tmsi1]:
                self.imsi_seen(self.tmsis[tmsi1], arfcn)
            if self.show_all_tmsi:
                do_print = False
                if tmsi1 and tmsi1 not in self.tmsis:
                    do_print = True
                    self.tmsis[tmsi1] = ""
                if tmsi1 and tmsi1 not in self.tmsis:
                    do_print = True
                    self.tmsis[tmsi2] = ""
                if do_print:
                    self.pfields(str(n), tmsi1, tmsi2, None, str(self.mcc), str(self.mnc), str(self.lac), str(self.cell), p)

    def imsi_seen(self, imsi, arfcn):
        now = datetime.datetime.utcnow().replace(microsecond=0)
        imsi, mcc, mnc = self.decode_imsi(imsi)
        if imsi in self.imsistate:
            self.imsistate[imsi]["lastseen"] = now
        else:
            self.imsistate[imsi] = {
                "firstseen": now,
                "lastseen": now,
                "imsi": imsi,
                "arfcn": arfcn,
            }
        self.imsi_purge_old()

    def imsi_purge_old(self):
        now = datetime.datetime.utcnow().replace(microsecond=0)
        maxage = datetime.timedelta(minutes=self.purgeTimer)
        limit = now - maxage
        remove = [imsi for imsi in self.imsistate if limit > self.imsistate[imsi]["lastseen"]]
        for k in remove:
            del self.imsistate[k]


class gsmtap_hdr(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("version", ctypes.c_ubyte),
        ("hdr_len", ctypes.c_ubyte),
        ("type", ctypes.c_ubyte),
        ("timeslot", ctypes.c_ubyte),
        ("arfcn", ctypes.c_uint16),
        ("signal_dbm", ctypes.c_ubyte),
        ("snr_db", ctypes.c_ubyte),
        ("frame_number", ctypes.c_uint32),
        ("sub_type", ctypes.c_ubyte),
        ("antenna_nr", ctypes.c_ubyte),
        ("sub_slot", ctypes.c_ubyte),
        ("res", ctypes.c_ubyte),
    ]

    def __repr__(self):
        return "%s(version=%d, hdr_len=%d, type=%d, timeslot=%d, arfcn=%d, signal_dbm=%d, snr_db=%d, frame_number=%d, sub_type=%d, antenna_nr=%d, sub_slot=%d, res=%d)" % (
            self.__class__, self.version, self.hdr_len, self.type,
            self.timeslot, self.arfcn, self.signal_dbm, self.snr_db,
            self.frame_number, self.sub_type, self.antenna_nr, self.sub_slot,
            self.res,
        )


def find_cell(gsm, udpdata, t=None):
    global mcc
    global mnc
    global lac
    global cell
    global country
    global brand
    global operator

    if gsm.sub_type == 0x01:
        p = bytearray(udpdata)
        if p[0x12] == 0x1b:
            m = hex(p[0x15])
            if len(m) < 4:
                mcc = m[2] + '0'
            else:
                mcc = m[3] + m[2]
            mcc += str(p[0x16] & 0x0f)

            m = hex(p[0x17])
            if len(m) < 4:
                mnc = m[2] + '0'
            else:
                mnc = m[3] + m[2]

            lac = p[0x18] * 256 + p[0x19]
            cell = p[0x13] * 256 + p[0x14]
            t.current_cell(mcc, mnc, lac, cell)


def find_imsi(udpdata, t=None):
    if t is None:
        t = imsitracker

    gsm = gsmtap_hdr.from_buffer_copy(udpdata)
    if gsm.sub_type == 0x1:
        find_cell(gsm, udpdata, t=t)
    else:
        p = bytearray(udpdata)
        tmsi1 = ""
        tmsi2 = ""
        imsi1 = ""
        imsi2 = ""
        if p[0x12] == 0x21:
            if p[0x14] == 0x08 and (p[0x15] & 0x1) == 0x1:
                imsi1 = p[0x15:][:8]
                if p[0x10] == 0x59 and p[0x1E] == 0x08 and (p[0x1F] & 0x1) == 0x1:
                    imsi2 = p[0x1F:][:8]
                elif p[0x10] == 0x4d and p[0x1E] == 0x05 and p[0x1F] == 0xf4:
                    tmsi1 = p[0x20:][:4]

                t.register_imsi(gsm.arfcn, imsi1, imsi2, tmsi1, tmsi2, p)

            elif p[0x1B] == 0x08 and (p[0x1C] & 0x1) == 0x1:
                tmsi1 = p[0x16:][:4]
                imsi2 = p[0x1C:][:8]
                t.register_imsi(gsm.arfcn, imsi1, imsi2, tmsi1, tmsi2, p)

            elif p[0x14] == 0x05 and (p[0x15] & 0x07) == 4:
                tmsi1 = p[0x16:][:4]
                if p[0x1B] == 0x05 and (p[0x1C] & 0x07) == 4:
                    tmsi2 = p[0x1D:][:4]
                else:
                    tmsi2 = ""

                t.register_imsi(gsm.arfcn, imsi1, imsi2, tmsi1, tmsi2, p)

        elif p[0x12] == 0x22:
            if p[0x1D] == 0x08 and (p[0x1E] & 0x1) == 0x1:
                tmsi1 = p[0x14:][:4]
                tmsi2 = p[0x18:][:4]
                imsi2 = p[0x1E:][:8]
                t.register_imsi(gsm.arfcn, imsi1, imsi2, tmsi1, tmsi2, p)


def udpserver(port, prn):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('localhost', port)
    sock.bind(server_address)
    while True:
        udpdata, address = sock.recvfrom(4096)
        if prn:
            prn(udpdata)


def find_imsi_from_pkt(p):
    udpdata = bytes(p[UDP].payload)
    find_imsi(udpdata)


if __name__ == "__main__":
    imsitracker = tracker()
    parser = OptionParser(usage="%prog: [options]")
    parser.add_option("-a", "--alltmsi", action="store_true", dest="show_all_tmsi", help="Show TMSI who haven't got IMSI (default  : false)")
    parser.add_option("-i", "--iface", dest="iface", default="lo", help="Interface (default : lo)")
    parser.add_option("-m", "--imsi", dest="imsi", default="", type="string", help='IMSI to track (default : None, Example: 123456789101112 or "123 45 6789101112")')
    parser.add_option("-p", "--port", dest="port", default="4729", type="int", help="Port (default : 4729)")
    parser.add_option("-s", "--sniff", action="store_true", dest="sniff", help="sniff on interface instead of listening on port (require root/suid access)")
    parser.add_option("-w", "--sqlite", dest="sqlite", default=None, type="string", help="Save observed IMSI values to specified SQLite file")
    parser.add_option("-t", "--txt", dest="txt", default=None, type="string", help="Save observed IMSI values to specified TXT file")
    (options, args) = parser.parse_args()

    if options.sqlite:
        imsitracker.sqlite_file(options.sqlite)

    if options.txt:
        imsitracker.textfile(options.txt)

    imsitracker.show_all_tmsi = options.show_all_tmsi
    imsi_to_track = ""
    if options.imsi:
        imsi = "9" + options.imsi.replace(" ", "")
        imsi_to_track_len = len(imsi)
        if imsi_to_track_len % 2 == 0 and imsi_to_track_len > 0 and imsi_to_track_len < 17:
            for i in range(0, imsi_to_track_len - 1, 2):
                imsi_to_track += chr(int(imsi[i + 1]) * 16 + int(imsi[i]))
            imsi_to_track_len = len(imsi_to_track)
        else:
            print("Wrong size for the IMSI to track!")
            print("Valid sizes :")
            print("123456789101112")
            print("1234567891011")
            print("12345678910")
            print("123456789")
            print("1234567")
            print("12345")
            print("123")
            exit(1)
    imsitracker.track_this_imsi(imsi_to_track)
    if options.sniff:
        imsitracker.header()
        sniff(iface=options.iface, filter="port {} and not icmp and udp".format(options.port), prn=find_imsi_from_pkt, store=0)
    else:
        imsitracker.header()
        udpserver(port=options.port, prn=find_imsi)
