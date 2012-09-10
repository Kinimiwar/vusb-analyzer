#
# VUsbTools.Decoders.Hub
# Aaron Rolett <arolett@vmware.com>
#
# Decodes the hub protocol.
#
# Copyright (C) 2005-2012 VMware, Inc. Licensed under the MIT
# License, please see the README.txt. All rights reserved.
#

from VUsbTools import Decode, Struct


class HubControlDecoder(Decode.ControlDecoder):
    """Decodes the control endpoint on USB hubs.
    """
    classRequests = Struct.EnumDict({
        0x00: 'HubGetStatus',
        0x01: 'HubClearFeature',
        0x03: 'HubSetFeature',
        0x06: 'HubGetDescriptor',
        0x07: 'HubSetDescriptor',
        })

    hubStatus = Struct.EnumDict({
        0x0: 'LocalPowerSource',
        0x1: 'OverCurrent',
        })

    hubChange = Struct.EnumDict({
        0x0: 'LocalPowerSource',
        0x1: 'OverCurrent',
        })


    hubFeature = Struct.EnumDict({
        0x0: 'CHubLocalPower',
        0x1: 'CHubOverCurrent',
        })

    portStatus = Struct.EnumDict({
        0x0: 'ConnectStatus',
        0x1: 'PortEnable',
        0x2: 'Suspend',
        0x3: 'OverCurrent',
        0x4: 'Reset',
        0x8: 'PortPower',
        0x9: 'LowSpeedDeviceAttached',
        0xA: 'HighSpeedDeviceAttached',
        0xB: 'PortTestMode',
        0xC: 'PortIndicatorControl'
        })

    portChange = Struct.EnumDict({
        0x0: 'ConnectStatus',
        0x1: 'PortEnable',
        0x2: 'Suspend',
        0x3: 'OverCurrent',
        0x4: 'Reset',
        })

    portFeature = Struct.EnumDict({
        0x0:  'PortConnection',
        0x1:  'PortEnable',
        0x2:  'PortSuspend',
        0x3:  'PortOverCurrent',
        0x4:  'PortReset',
        0x8:  'PortPower',
        0x9:  'PortLowSpeed',
        0x10: 'CPortConnection',
        0x11: 'CPortEnable',
        0x12: 'CPortSuspend',
        0x13: 'CPortOverCurrent',
        0x14: 'CPortReset',
        0x15: 'PortTest',
        0x16: 'PortIndicator',
        })


    def expandBitFields(self, descStr, fields, fieldNames):
        for (bit, name) in fieldNames.iteritems():
            descStr += "\n\t%s(%d)" % (name, (fields >> bit) & 0x1)
        return descStr


    def decode_HubClearFeature(self, setup):
        if setup.recip == "other":
            setup.event.pushDecoded("Hub PortClearFeature(port=%d, feature=%s)" %
                                    (setup.wIndex & 0xFF,
                                     self.portFeature[setup.wValue]))
        else:
            setup.event.pushDecoded("Hub HubClearFeature(feature=%s)" %
                                    (self.hubFeature[setup.wValue]))


    def decode_HubSetFeature(self, setup):
        if setup.recip == "other":
            setup.event.pushDecoded("Hub PortSetFeature(port=%d, feature=%s)" %
                                    (setup.wIndex & 0xFF,
                                     self.portFeature[setup.wValue]))
        else:
            setup.event.pushDecoded("Hub HubSetFeature(feature=%s)" %
                                    (self.hubFeature[setup.wValue]))


    def decode_HubGetStatus(self, setup):
        fields = Struct.Group(None,
                              Struct.UInt16("status"),
                              Struct.UInt16("change"))
        fields.decode(setup.event.data[8:])
        if setup.recip == "other":
            setup.event.pushDecoded("Hub PortGetStatus(port=%d, connect=%d)" %
                                    (setup.wIndex,
                                     fields.status & 0x1))
            portStatusDesc = self.expandBitFields("PortStatus:", fields.status,
                                                  self.portStatus)
            setup.event.appendDecoded(portStatusDesc)
            portChangeDesc = self.expandBitFields("PortChange:", fields.change,
                                                  self.portChange)
            setup.event.appendDecoded(portChangeDesc)
        else:
            setup.event.pushDecoded("Hub HubGetStatus")
            hubStatusDesc = self.expandBitFields("HubStatus:", fields.status,
                                                 self.hubStatus)
            setup.event.appendDecoded(hubStatusDesc)
            hubChangeDesc = self.expandBitFields("HubChange:", fields.change,
                                                 self.hubChange)
            setup.event.appendDecoded(hubChangeDesc)


def detector(context):
    #
    # Look for a hub and decode requests if a hub is found.
    #

    if (context.device and
        context.device.bDeviceClass == 0x09):

        if not context.endpoint:
            return HubControlDecoder(context.devInstance)
