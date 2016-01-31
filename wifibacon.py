#!/usr/bin/env python
# gets wifi beacons
# threaded and in wx
from scapy.all import *
import os, sys, signal, wx, time
from threading import Thread
from wx.lib.pubsub import setuparg1
from wx.lib.pubsub import pub as Publisher

ap_list = {}
client_list = {}
iface = "wlan0"
capturingPackets  = False

# ################################################################################
class SniffThread(Thread):
  def __init__(self):
    Thread.__init__(self)
    global capturingPackets
    self.start()

  def PcapStopFilter(self, x):
    return capturingPackets == False

  def run(self):
    sniff(iface=iface, prn = self.packetHandler) #, stop_filter = self.PcapStopFilter)

  # our packet analysis
  def packetHandler(self, pkt):
    if pkt.haslayer(Dot11):
      if pkt.type == 0 and pkt.subtype == 8: # add AP
        if not ap_list.has_key(pkt.addr2):
          ap_list[pkt.addr2] = pkt.info
          wx.CallAfter(Publisher.sendMessage, "addAp", '%s - %s' % (pkt.addr2, pkt.info))
          print "AP Mac: %s with SSID %s" %(pkt.addr2, pkt.info)
          print "total AP's:", len(ap_list.keys())

      if pkt.haslayer(Dot11ProbeReq):
        if pkt.haslayer(Dot11Elt):
          if pkt.ID == 0:
            if str(pkt.info) == "":
              # print pkt.show()
              a = 1
            else:
              # a client send a probe request
              if client_list.has_key(pkt.addr2):
                ssids = client_list.get(pkt.addr2)
                if pkt.info not in ssids:
                  ssids.append(pkt.info)
                  client_list[pkt.addr2] = ssids
                  print "Probe: %s with SSID %s" %(pkt.addr2, pkt.info)
                  wx.CallAfter(Publisher.sendMessage, "addClient", '%s - %s' % (pkt.addr2, pkt.info))
              else:
                # we dont have this client
                client_list[pkt.addr2] = [pkt.info]
                print "Probe: %s with SSID %s" %(pkt.addr2, pkt.info)
                wx.CallAfter(Publisher.sendMessage, "addClient", '%s - %s' % (pkt.addr2, pkt.info))
              print "total clients:", len(client_list.keys())
          elif pkt.ID == 3:
            print "Channel", ord(pkt.info)
          elif pkt.ID == 48:
            print "WPA2"
    
# ################################################################################
class MainWindow(wx.Frame):
  def __init__(self, parent, title):
    wx.Frame.__init__(self, None, wx.ID_ANY, "WIFI bac0n", size=(500,300))
    panel = wx.Panel(self, wx.ID_ANY)
    self.apListBox = wx.ListBox(choices=[], parent = panel, pos=wx.Point(8,48), size=(232,100))
    self.clientListBox = wx.ListBox(choices=[], parent = panel, pos=wx.Point(250,48), size=(232,100))

    # button to start sniffing
    self.sniffButton = wx.Button(id=5, label=u'Sniff', parent=panel, pos=wx.Point(8,8))
    self.sniffButton.Bind(wx.EVT_BUTTON, self.ClickSniffButton, id=5)

    Publisher.subscribe(self.AddAp, "addAp")
    Publisher.subscribe(self.AddClient, "addClient")
                            
    self.Show(True)

  def AddAp(self, msg):
    self.apListBox.Append(msg.data)

  def AddClient(self, msg):
    self.clientListBox.Append(msg.data)

  def ClickSniffButton(self, event):
    SniffThread()
    btn = event.GetEventObject()
    btn.Disable()

# ################################################################################
def setWlanMon(iface="wlan0", mode = True):
  try:
    os.system('ifconfig %s down' % iface) 
    os.system('iwconfig %s mode %s' % (iface, 'monitor' if mode else 'managed'))
    os.system('ifconfig %s up' % iface)
  except Exception:
    print "Something went wrong setting %s in monitor mode" % iface

def ctrl_c(signal, frame):
  print "Shutting down.."
  setWlanMon(iface, False)
  sys.exit(0);

if __name__ == "__main__":  
  if os.geteuid() != 0:
    print "[!] Please run this script as root"
    exit();
  if len(sys.argv) > 1:
    iface = sys.argv[1]
  signal.signal(signal.SIGINT, ctrl_c)
  setWlanMon(iface)
  capturingPackets = False

  # start our wx app
  app = wx.App(False)
  frame = MainWindow(None, "WIFI Bacon")
  app.MainLoop()


