import subprocess
import psutil
import sys
import time


def main():
    radio = sys.argv[1]
    band = sys.argv[2]
    # start and process things, then wait
    p = subprocess.Popen("/usr/local/bin/grgsm_scanner --args=" + radio + " -b " + band, shell=True)
    print("Happens while running")
    p.communicate()  # now wait plus that you can send commands to process
    print("after comand done")

    channels = open("channels.txt", "r")
    parsing = channels.read()
    k = 0
    for c in parsing.split("\n"):
        line = c.split(",")
        if (k > 0 and k < len(c)):
            for i in line:
                col = i.split(":")
                if (col[0].strip() == "Freq"):
                    p = subprocess.Popen("grgsm_livemon_headless --args=" + radio + " -f " + col[1].strip() + " > /dev/null 2>&1", shell=True)
                    print("Sniffing " + col[1].strip() + "...")
                    x = subprocess.Popen("sudo python3 utils.py --sniff -t sniff-" + col[1].strip() + ".txt", shell=True)
                    time.sleep(20)
                    kill(p.pid)
                    kill(x.pid)

                    sniff = open("sniff-" + col[1].strip() + ".txt", "r")
                    packt = sniff.read()

                    if len(packt.split("\n")) > 2:
                        print("Got packet.. mark as [OK]")
                        result = open("kal-" + radio.replace("=", "") + "-" + band + ".txt", "a")
                        result.write(col[1].strip() + " " + str(len(packt.split("\n"))) + "\n")
                        result.close()
                        print("Freq " + col[1].strip() + " [SUCCESS]..")
                        print("\n")
                        continue
                    else:
                        print("Freq " + col[1].strip() + " [FAIL]..")
                        print("\n")
        k = k + 1


def kill(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()


if __name__ == '__main__':
    main()
