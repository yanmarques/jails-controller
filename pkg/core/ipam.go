package controller

import (
	"fmt"
	"net/netip"
	"time"
)

type IPSlot struct {
	IP        netip.Addr
	InUse     bool
	Consumer  string
	Timestamp time.Time
	Reserved  bool
}

type IPManager struct {
	Slots    []IPSlot
	Network  netip.Prefix
	LastSlot int
	Ttl      time.Duration
}

func NewIPManager(prefix string, ttl time.Duration) (*IPManager, error) {
	network, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, err
	}

	return &IPManager{
		Slots:    []IPSlot{},
		Network:  network,
		LastSlot: 0,
		Ttl:      ttl,
	}, nil
}

func (i *IPManager) AllocateIP(consumer string) (*netip.Addr, error) {
	now := time.Now()

	for idx := range i.Slots {
		slot := &i.Slots[idx]
		if slot.Reserved || slot.InUse {
			continue
		}

		elapsed := now.Sub(slot.Timestamp)
		if elapsed > i.Ttl || slot.Consumer == consumer {
			slot.InUse = true
			slot.Consumer = consumer
			slot.Timestamp = time.Now()
			return &slot.IP, nil
		}
	}

	var addr netip.Addr
	if len(i.Slots) == 0 {
		addr = i.Network.Addr().Next()
		i.LastSlot = 0
	} else {
		lastInSlot := i.Slots[i.LastSlot]
		addr = lastInSlot.IP.Next()
	}

	if !i.Network.Contains(addr) {
		return nil, fmt.Errorf("ipmanager: no more IPs available")
	}

	i.LastSlot = len(i.Slots)
	i.Slots = append(i.Slots, IPSlot{
		IP:        addr,
		InUse:     true,
		Consumer:  consumer,
		Timestamp: now,
		Reserved:  false,
	})

	return &addr, nil
}

func (i *IPManager) FindAllocation(consumer string) (netip.Addr, error) {
	for idx := range i.Slots {
		slot := &i.Slots[idx]
		if slot.Consumer == consumer && slot.InUse {
			return slot.IP, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("consumer %s did not allocate any ip address", consumer)
}

func (i *IPManager) Free(ipAddr netip.Addr) error {
	for idx := range i.Slots {
		slot := &i.Slots[idx]
		if slot.IP == ipAddr {
			if slot.Reserved {
				return nil
			}

			slot.InUse = false
			slot.Timestamp = time.Now()
			return nil
		}
	}

	return fmt.Errorf("unknown IP address: %v", ipAddr)
}

func (i *IPManager) Import(consumer string, ipAddr netip.Addr) error {
	if !i.Network.Contains(ipAddr) {
		return fmt.Errorf("IP address %v is outside the network: %v", ipAddr.String(), i.Network.String())
	}

	for idx := range i.Slots {
		slot := &i.Slots[idx]
		if slot.IP == ipAddr {
			if slot.InUse && slot.Consumer != consumer {
				return fmt.Errorf("ip address %s already in use by %s", ipAddr.String(), consumer)
			}

			slot.Timestamp = time.Now()
			slot.InUse = true
			slot.Reserved = false
			return nil
		}
	}

	if len(i.Slots) > 0 {
		lastInSlot := i.Slots[i.LastSlot]
		if ipAddr.Compare(lastInSlot.IP) > 0 {
			i.LastSlot = len(i.Slots)
		}
	}

	i.Slots = append(i.Slots, IPSlot{
		IP:        ipAddr,
		InUse:     true,
		Consumer:  consumer,
		Timestamp: time.Now(),
		Reserved:  false,
	})

	return nil
}

func (i *IPManager) ReserveStatic(consumer string, ipAddr netip.Addr) error {
	if !i.Network.Contains(ipAddr) {
		return fmt.Errorf("IP address %v is outside the network: %v", ipAddr.String(), i.Network.String())
	}

	for idx := range i.Slots {
		slot := &i.Slots[idx]
		if slot.IP == ipAddr {
			if slot.Consumer != consumer {
				return fmt.Errorf("ip address %s already reserved for: %s", ipAddr.String(), consumer)
			}

			slot.Timestamp = time.Now()
			slot.InUse = true
			slot.Reserved = true
			return nil
		}
	}

	if len(i.Slots) > 0 {
		lastInSlot := i.Slots[i.LastSlot]
		if ipAddr.Compare(lastInSlot.IP) > 0 {
			i.LastSlot = len(i.Slots)
		}
	}

	i.Slots = append(i.Slots, IPSlot{
		IP:        ipAddr,
		InUse:     true,
		Consumer:  consumer,
		Timestamp: time.Now(),
		Reserved:  true,
	})

	return nil
}
