import pyping
import os
import nmap

try:
    path = raw_input("Path of IP List: ")
except KeyboardInterrupt as e:
    print(e)
try:
    rpath = raw_input("Provide a path to store data: ")
except Exception as e:
    print(e)
ip_addr = []
file = open(path, 'r')
data = file.readlines()
i = 0;
while i < len(data):
    actdata = data[i].rstrip()
    ip_addr.append(actdata)
    i = i + 1
file.close()

relpath = rpath + "/nmap"
inputpath = os.path.expanduser("~") + "/" + relpath
down = inputpath + "/" + "ip_status_down.txt"
up = inputpath + "/" + "ip_status_up.txt"


# ==================================================================================================
class nmap_scanner:
    path_storage = []

    def nmap(self, args):
        discovery = "-A -sV -sC -Pn -sC -Pn script=discovery -T5 -oN " + nmap_scanner().path_storage[
            0] + "discovery_scan_result.txt"
        vuln = "-A -O -sV -sC -Pn -sC -Pn script=vuln -oN " + nmap_scanner().path_storage[0] + "vuln_scan_result.txt"
        httpauth = "-A -O -sV -sC -Pn -sC -Pn script=http-auth.nse -oN " + nmap_scanner().path_storage[
            0] + "httpauth_scan_result.txt"
        default = "-A -O -sV -sC -Pn -sC -Pn script=default -oN " + nmap_scanner().path_storage[
            0] + "default_scan_result.txt"
        fuzzer = "-A -O -sV -sC -Pn -sC -Pn script=fuzzer -oN " + nmap_scanner().path_storage[
            0] + "fuzzer_scan_result.txt"
        malware = "-A -O -sV -sC -Pn -sC -Pn script=malware -oN " + nmap_scanner().path_storage[
            0] + "malware_scan_result.txt"
        exploit = "-A -O -sV -sC -Pn -sC -Pn script=exploit -oN " + nmap_scanner().path_storage[
            0] + "exploit_scan_result.txt"
        poodle = "-sV -Pn --version-light --script ssl-poodle -p 443 -oN " + nmap_scanner().path_storage[
            0] + "poodle_scan_result.txt"
        ciphers = "-sV -Pn --script ssl-enum-ciphers -p 443 -oN " + nmap_scanner().path_storage[
            0] + "ciphers_scan_result.txt"

        print(args)
        nm = nmap.PortScanner()
        ipset = " ".join(args)
        print(nmap_scanner().path_storage[0])
        print("performing discovery scan")
        nm.scan(ipset, arguments=discovery)
        print(nm.scanstats())
        print("=====================================")
        print("performing vuln scan")
        nm.scan(ipset, arguments=vuln)
        print(nm.scanstats())
        print("=====================================")
        print("performing httpauth scan")
        nm.scan(ipset, arguments=httpauth)
        print(nm.scanstats())
        print("=====================================")
        print("performing default scan")
        nm.scan(ipset, arguments=default)
        print(nm.scanstats())
        print("=====================================")
        print("performing fuzzer scan")
        nm.scan(ipset, arguments=fuzzer)
        print(nm.scanstats())
        print("=====================================")
        print("performing malware scan")
        nm.scan(ipset, arguments=malware)
        print(nm.scanstats())
        print("=====================================")
        print("performing exploit scan")
        nm.scan(ipset, arguments=exploit)
        print(nm.scanstats())
        print("=====================================")
        print("performing poodle scan")
        nm.scan(ipset, arguments=poodle)
        print(nm.scanstats())
        print("=====================================")
        print("performing ciphers scan")
        nm.scan(ipset, arguments=ciphers)
        print(nm.scanstats())
        print("=====================================")


# ==================================================================================================

class nmapiploader:
    ipstorage = []
    scan_results_dir = inputpath + "/" + "set_"

    def ippusher(self):
        i = 0;
        while i < len(nmapiploader().ipstorage):
            ipset = nmapiploader().ipstorage[i]
            fpath = nmapiploader().scan_results_dir + str(i) + "/"
            nmap_scanner().path_storage.insert(0, fpath)
            os.makedirs(fpath)
            nmap_scanner().nmap(ipset)
            i = i + 1

    def iploader(self):
        ray = []
        i = 5
        j = 5
        with open(up, "r") as ip:
            data = ip.readlines()
            k = 0
            while k < len(data):
                ray.append(data[k].rstrip())
                k = k + 1
            ip.close()
        print("=====================================")
        nmapiploader().ipstorage.append(ray[:i])
        while i < len(ray):
            if len(ray[:i]) >= 5:
                j = j + 5
                print("=====================================")
            nmapiploader().ipstorage.append(ray[i:j])
            i = i + 5
        self.ippusher()


# ==================================================================================================

class checkup:
    dwnip = []

    def nmapcheckup(self):
        with open(down, "r") as dwn:
            lineitem = dwn.readlines()
            i = 0;
            while i < len(lineitem):
                nlineitem = lineitem[i].rstrip()
                self.dwnip.append(nlineitem)
                i = i + 1
            dwn.close()
        print("=====================================")
        self.nmapipstatus()

    def nmapipstatus(self):
        for ip in checkup.dwnip:
            # print(ip)
            nm = nmap.PortScanner()
            nm.scan(ip, arguments="-Pn -vv -O -T5 ")
            stats = nm.scanstats()
            # print(stats)
            for c in stats:
                if stats[c] == "1":
                    print(ip)
                    print "IP state: " + c + " ==> " + stats[c]
                    with open(up, "a") as iup:
                        iup.write(ip + "\n")
                        iup.close()
                break
        nmapiploader().iploader()


# ==================================================================================================

def ping(ip):
    png = pyping.ping(ip)
    if png.ret_code == 0:
        with open(up, "a") as iup:
            iup.write(ip + "\n")
            iup.close()
            print "ping status up"
            print("=====================================")
    elif png.ret_code != 0:
        with open(down, "a") as dwn:
            dwn.write(ip + "\n")
            dwn.close()
            print "ping status down"
            print("=====================================")


# ==================================================================================================

def caller():
    for ip in ip_addr:
        print ip
        ping(ip)
    try:
        if os.path.getsize(down) != 0 and os.path.getsize(up) != 0:
            checkup().nmapcheckup()
        elif os.path.getsize(down) != 0:
            checkup().nmapcheckup()
    except:
        print("none of the ip in the list is down")
        if os.path.getsize(up) != 0:
            nmapiploader().iploader()


# ==================================================================================================
#
if os.path.exists(inputpath):
    if os.path.isfile(down) and os.path.isfile(up):
        os.remove(up)
        os.remove(down)
    elif os.path.isfile(down):
        os.remove(down)
    elif os.path.isfile(up):
        os.remove(up)
        caller()
else:
    os.makedirs(inputpath)
    caller()
