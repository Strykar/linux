ccflags-y := -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt'
ccflags-$(CONFIG_WIREGUARD_DEBUG) += -DDEBUG
wireguard-y := main.o
wireguard-y += noise.o
wireguard-y += device.o
wireguard-y += peer.o
wireguard-y += timers.o
wireguard-y += queueing.o
wireguard-y += send.o
wireguard-y += receive.o
wireguard-y += socket.o
wireguard-y += peerlookup.o
wireguard-y += allowedips.o
wireguard-y += ratelimiter.o
wireguard-y += cookie.o
wireguard-y += netlink.o generated/netlink.o
ifeq ($(CONFIG_WIREGUARD),m)
wireguard-$(CONFIG_DEBUG_INFO_BTF_MODULES) += bpf.o
else ifeq ($(CONFIG_WIREGUARD),y)
wireguard-$(CONFIG_DEBUG_INFO_BTF) += bpf.o
endif
obj-$(CONFIG_WIREGUARD) := wireguard.o
