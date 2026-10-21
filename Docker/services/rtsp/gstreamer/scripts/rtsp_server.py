#!/usr/bin/env python3
"""GStreamer RTSP server using the standard gst-rtsp-server bindings.

Serves a synthetic H.264 test pattern at rtsp://host:8554/live. The SDP and
OPTIONS method set differ from MediaMTX, which is the point of this variant.
"""

import gi

gi.require_version("Gst", "1.0")
gi.require_version("GstRtspServer", "1.0")
from gi.repository import Gst, GstRtspServer, GLib

Gst.init(None)

server = GstRtspServer.RTSPServer()
server.set_address("0.0.0.0")
server.set_service("8554")

factory = GstRtspServer.RTSPMediaFactory()
factory.set_launch(
    "( videotestsrc is-live=true ! videoconvert ! x264enc tune=zerolatency ! "
    "rtph264pay name=pay0 pt=96 )"
)
factory.set_shared(True)

server.get_mount_points().add_factory("/live", factory)
server.attach(None)

print("GStreamer RTSP server on rtsp://0.0.0.0:8554/live", flush=True)
GLib.MainLoop().run()
