TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Outlaw
Outlaw_FILES = Tweak.xm
Outlaw_CFLAGS = -fobjc-arc -Iinclude
Outlaw_LDFLAGS = -Llib -lsubstrate

include $(THEOS_MAKEPATH)/tweak.mk
