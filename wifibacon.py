#!/usr/bin/env python
# gets wifi beacons
# threaded and in wx
# more info - @ndrix

from scapy.all import *
import os, sys, signal, wx, time, subprocess
from threading import Thread
from wx.lib.pubsub import setuparg1
from wx.lib.pubsub import pub as Publisher

ap_list = {}
client_list = {}
interfaces = []
capturingPackets  = False

# ################################################################################
class SniffThread(Thread):
  def __init__(self, iface):
    Thread.__init__(self)
    global capturingPackets
    self.iface = str(iface)
    self.channel = 1
    self.counter = 0
    self.start()
    
  def PcapStopFilter(self, x):
    return capturingPackets == False

  def run(self):
    sniff(iface=self.iface, prn = self.packetHandler, stop_filter = self.PcapStopFilter)

  # our packet analysis
  def packetHandler(self, pkt):
    if pkt.haslayer(Dot11):
      if pkt.type == 0 and pkt.subtype == 8: # add AP
        if not ap_list.has_key(pkt.addr2):
          ap_list[pkt.addr2] = pkt.info
          wx.CallAfter(Publisher.sendMessage, "addAp", '%s - %s' % (pkt.addr2, pkt.info))
          print "AP Mac: %s with SSID %s" %(pkt.addr2, pkt.info)
          print "total AP's:", len(ap_list.keys())

        if pkt.ID == 3:
          print "Channel", ord(pkt.info)
        elif pkt.ID == 48:
          print "WPA2"

      # if pkt.haslayer(Dot11ProbeReq):
      if pkt.type == 0 and pkt.subtype == 4: 
        if pkt.haslayer(Dot11Elt):
          if pkt.ID == 0:
            if str(pkt.info) == "":
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

    # change the channel every X packets
    self.counter += 1
    if self.counter % 100 is 0:
      self.counter = 0
      self.channel += 1
      if self.channel == 14:
        self.channel = 1
      os.system('iwconfig %s channel %d' % (self.iface, self.channel))
      print "Now running on channel %d" % self.channel
    
# ################################################################################
class MainWindow(wx.Frame):
  def __init__(self, parent, title):
    wx.Frame.__init__(self, None, wx.ID_ANY, "WIFI bac0n", size=(500,300))
    self.Bind(wx.EVT_CLOSE, self.OnClose)

    panel = wx.Panel(self, wx.ID_ANY)
    self.apListBox = wx.ListBox(choices=[], parent = panel, pos=wx.Point(8,48), size=(232,200))
    self.clientListBox = wx.ListBox(choices=[], parent = panel, pos=wx.Point(250,48), size=(232,200))

    # list of interfaces
    self.ifaceListBox = wx.ComboBox(choices=interfaces, value=interfaces[0], parent = panel, pos = wx.Point(8,8), size=(100, 30))

    # button to start sniffing
    self.sniffButton = wx.Button(id=5, label='Start capture', parent=panel, pos=wx.Point(120,8))
    self.sniffButton.Bind(wx.EVT_BUTTON, self.ClickSniffButton, id=5)

    Publisher.subscribe(self.AddAp, "addAp")
    Publisher.subscribe(self.AddClient, "addClient")

    self.Show(True)

  def OnClose(self, event):
    self.setWlanMon(self.ifaceListBox.GetValue(), False)
    sys.exit(0);
    

  def AddAp(self, msg):
    self.apListBox.Append(msg.data)

  def AddClient(self, msg):
    self.clientListBox.Append(msg.data)

  # set or bring adapter out of monitor mode
  def setWlanMon(self, iface, mode = True):
    try:
      os.system('ifconfig %s down' % iface) 
      os.system('iwconfig %s mode %s' % (iface, 'monitor' if mode else 'managed'))
      os.system('ifconfig %s up' % iface)
    except Exception:
      msg = "Something went wrong setting %s in monitor mode" % iface
      dlg = wx.MessageDialog(self, msg, "Warning", wx.OK | wx.ICON_WARNING)
      dlg.ShowModal()
      dlg.Destroy()
      return False
    return True
    
  def ClickSniffButton(self, event):
    global capturingPackets
    global iface
    if capturingPackets == False:
      if self.setWlanMon(self.ifaceListBox.GetValue(), True):
        print "[-] Started capture"
        self.sniffButton.SetLabel("Stop capture")
        self.ifaceListBox.Disable()
        SniffThread(self.ifaceListBox.GetValue())
        capturingPackets = True
    else:
      # we're capturing already, stop it
      print "[-] Stopped capture"
      self.ifaceListBox.Enable()
      capturingPackets = False
      self.sniffButton.SetLabel("Start capture")
        



# ################################################################################

if __name__ == "__main__":  
  if os.geteuid() != 0:
    print "[!] Please run this script as root"
    exit();

  # populate our list of WLAN cards
  try:
    out, err = subprocess.Popen('iwconfig', stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    for line in out.splitlines():
      if "IEEE 802.11" in line:
        interfaces.append(line.partition(' ')[0])
  except Exception:
    print "can't run iwconfig"

  capturingPackets = False

  # start our wx app
  app = wx.App(False)
  frame = MainWindow(None, "WIFI Bacon")
  app.MainLoop()


