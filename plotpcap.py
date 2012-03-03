from dpkt.ethernet import Ethernet
from dpkt.ip import IP
import dpkt.tcp
import pcap
import struct
import sys

from matplotlib import pyplot

#TODO: Proper argument parsing
def usage():
    print "python plotpcap.py [filename] [x_axis] [y_axis] [tcpdump filter]"
    print "filename:        pcap file to plot"
    print "x_axis:          value to plot on the x_axis (either 'time', 'number')"
    print "y_axis:          value to plot on the y_axis (either 'ipid', 'tcptsval', 'ipid2')"
    print "tcpdump filter:  the tcpdump style filter string 'e.g. ip src [NAT gateway]"
    print ""
    print "plotpcap.py is a script for plotting TCP/IP field headers against packet numbers or timestamps"
    print "this can be used to help identify how many computers of what operating system are behind a NAT gateway"
    print ""
    print "tcpdump filter: The filter option is important as usually you'll only want to analyse traffic flowing in one direction"
    print "x_axis: ipid is good for identifying unique windows boxes, it plots the IP packet ID values"
    print "        tcptsval is good for unix boxes, it shows tcp segments with timestamp values"
    print "        ipid2 is the same as ipid but only shows tcp segments without timestamp values (makes ipid clearer)"
    print "y_axis: time is the pcap file timestamp"
    print "        number is the packet number (an incremental count of all packets that match the filter)"

def parse_args(argv):
    opts = {}
    allowed_x = ["time", "number"]
    allowed_y = ["ipid", "ipid2", "tcptsval"]
    opts["filename"] = argv.pop(0)
    opts["x_axis"] = argv.pop(0)
    if opts["x_axis"] not in allowed_x:
        print "Invalid x_axis: choose from %r" % allowed_x
        sys.exit(1)
    opts["y_axis"] = argv.pop(0)
    if opts["y_axis"] not in allowed_y:
        print "Invalid y_axis: choose from %r" % allowed_y
        sys.exit(1)
    opts["filter"] = " ".join(argv)
    return opts

if len(sys.argv) < 2:
    usage()
    sys.exit(1)
opts = parse_args(sys.argv[1:])

#filter_dict = { "ipid": "ip and ", "tcptsval": "tcp and ", "ipid2": "tcp and" }
print opts
#reader = Reader(open(opts["filename"], "rb")) # Does not actually implement setfilter :(
reader = pcap.pcap(opts["filename"])
reader.setfilter(opts["filter"])

plot_x = []
plot_y = [] 

for i, pcaptuple in enumerate(reader):
    ts, data = pcaptuple
    p = Ethernet(data)
    if type(p.data) != IP:
        continue

    p_opts = None
    if opts["y_axis"] == 'ipid':
        plot_y.append(p.data.id)

    elif opts["y_axis"] == 'ipid2':
        # only plot IPID of TCP segments (without timestamp options)
        if type(p.data.data) == dpkt.tcp.TCP:
            p_opts = dpkt.tcp.parse_opts(p.data.data.opts)
            ts_found = False
            for opt, val in p_opts:
                if opt == dpkt.tcp.TCP_OPT_TIMESTAMP:
                    ts_found = True
                    break
            if ts_found:
                continue
            plot_y.append(p.data.id)
        else:
            continue

    elif opts["y_axis"] == 'tcptsval':
        if type(p.data.data) != dpkt.tcp.TCP:
            continue
        v1 = None
        v2 = None
        p_opts = dpkt.tcp.parse_opts(p.data.data.opts)
        plot_y.append
        for opt, val in p_opts:
            if opt == dpkt.tcp.TCP_OPT_TIMESTAMP:
                v1, v2 = struct.unpack(">II", val)
                break
        if v1:
            plot_y.append(v1)
        else:
            continue
     
    if opts["x_axis"] == 'number':
        plot_x.append(i)
    elif opts["x_axis"] == 'time':
        plot_x.append(ts)

print len(plot_x)
fig = pyplot.figure()
plotout = pyplot.plot(plot_x, plot_y, '.')
pyplot.show()
