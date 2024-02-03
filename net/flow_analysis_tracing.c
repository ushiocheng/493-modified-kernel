#include <linux/flow_analysis_tracing.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <uapi/linux/in.h>
#include <linux/printk.h>

#define bool int
#define true 1
#define false 0

struct FlowID {
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	//// protocol: TCP
};

struct PacketData {
	// Flow ID
	struct FlowID flow;
	// Timing
	unsigned long time_received; // aka. T1
	unsigned long time_dispatched; // aka. T4
	unsigned long time_sent; // aka. T2
	// Additional Data
	size_t payload_size;
};

struct MatchingTableEntry {
	struct sk_buff *skb;
	struct PacketData *packetDataEntryPtr;
};

unsigned int matchingTableEntryUsed = 0;
struct MatchingTableEntry matchingTable[128];
struct PacketDataCLL {
	struct PacketData packetDataEntryPtr[256];
	unsigned int numUsed;
	struct PacketDataCLL *next;
};
struct PacketDataCLL *packetDataCLLHead = NULL;

void packetDataCLLAdd(struct PacketData *packetDataEntryPtr)
{
	struct PacketDataCLL *packetDataCLLHeadPtr = packetDataCLLHead;
	while (true) {
		if (packetDataCLLHeadPtr->numUsed < 256) {
			packetDataCLLHeadPtr->packetDataEntryPtr
				[packetDataCLLHeadPtr->numUsed] =
				*packetDataEntryPtr;
			packetDataCLLHeadPtr->numUsed++;
			return;
		}
		if (packetDataCLLHeadPtr->next == NULL) {
			packetDataCLLHeadPtr
				->next = (struct PacketDataCLL *)kmalloc(
				sizeof(struct PacketDataCLL),
				GFP_KERNEL); // maybe do GPF_USER to make it accessible in userland?
			packetDataCLLHeadPtr->next->numUsed = 0;
			packetDataCLLHeadPtr->next->next = NULL;
		}
		packetDataCLLHeadPtr = packetDataCLLHeadPtr->next;
	}
}

bool initialized = false;
void initializeDataStructures(void)
{
	if (initialized) {
		printk(KERN_ALERT "Unreachable: Data structures already initialized\n");
		return;
	}
	packetDataCLLHead = (struct PacketDataCLL *)kmalloc(
		sizeof(struct PacketDataCLL),
		GFP_KERNEL); // maybe do GPF_USER to make it accessible in userland?
	packetDataCLLHead->numUsed = 0;
	packetDataCLLHead->next = NULL;
	initialized = true;
}

/**
 * @brief Check if the ip is local
 * local ip: 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8
*/
bool isLocal(unsigned int ip)
{
	if (ip && 0x0000ffff == 0xc0a8) {
		return true;
	}
	if (ip && 0x0000f0ff == 0xac10) {
		return true;
	}
	if (ip && 0x000000ff == 0x0a) {
		return true;
	}
	return false;
}

/**
 * Hook for netif_receive_skb event
 * eth -> wlan T1
 * wlan -> eth T1
 */
void netif_receive_skb_hook(struct sk_buff *skb)
{
	printk(KERN_DEBUG "netif_receive_skb_hook(%p)\n", skb);
	if (!initialized) {
		initializeDataStructures();
	}
	if (matchingTableEntryUsed >= 128) {
		// matching table full
		return;
	}
	struct iphdr *_ip_hdr = ip_hdr(skb);
	if (_ip_hdr->protocol != IPPROTO_TCP) {
		// not TCP
		return;
	}
	struct PacketData *newPacketDataEntry = (struct PacketData *)kmalloc(
		sizeof(struct PacketData),
		GFP_KERNEL); // maybe do GPF_USER to make it accessible in userland?
	newPacketDataEntry->flow.src_ip = _ip_hdr->saddr;
	newPacketDataEntry->flow.dst_ip = _ip_hdr->daddr;
	newPacketDataEntry->time_received = ktime_get_ns();
	packetDataCLLAdd(newPacketDataEntry);
	// insert skb addr and packet data entry ptr into matching table
	matchingTable[matchingTableEntryUsed].skb = skb;
	matchingTable[matchingTableEntryUsed].packetDataEntryPtr =
		newPacketDataEntry;
	matchingTableEntryUsed++;
}
EXPORT_SYMBOL(netif_receive_skb_hook);

/**
 * Hook for ieee80211_xmit event
 * eth -> wlan T4
 * wlan -> eth NA
*/
void ieee80211_xmit_hook(struct sk_buff *skb)
{
	printk(KERN_DEBUG "ieee80211_xmit_hook(%p)\n", skb);
	// Find packet in matching table
	for (int i = 0; i < matchingTableEntryUsed; i++) {
		if (matchingTable[i].skb == skb) {
			// Found packet
			// update T4 if packet direction is eth->wlan
			if (!isLocal(
				    matchingTable[i]
					    .packetDataEntryPtr->flow.src_ip)) {
				matchingTable[i]
					.packetDataEntryPtr->time_dispatched =
					ktime_get_ns();
			}
			break;
		}
	}
	// packet not found in matching table, ignored
}
EXPORT_SYMBOL(ieee80211_xmit_hook);

/**
 * Hook for net_dev_xmit event
 * eth -> wlan NA
 * wlan -> eth T2
 */
void net_dev_xmit_hook(struct sk_buff *skb)
{
	printk(KERN_DEBUG "net_dev_xmit_hook(%p)\n", skb);
	// Find packet in matching table
	for (int i = 0; i < matchingTableEntryUsed; i++) {
		if (matchingTable[i].skb == skb) {
			// Found packet
			// update T2 if packet direction is wlan->eth
			if (isLocal(matchingTable[i]
					    .packetDataEntryPtr->flow.src_ip)) {
				matchingTable[i].packetDataEntryPtr->time_sent =
					ktime_get_ns();
				// remove packet from matching table
				matchingTable[i].skb =
					matchingTable[matchingTableEntryUsed - 1]
						.skb;
				matchingTable[i].packetDataEntryPtr =
					matchingTable[matchingTableEntryUsed - 1]
						.packetDataEntryPtr;
				matchingTableEntryUsed--;
			}
			return;
		}
	}
	// packet not found in matching table, ignored
}
EXPORT_SYMBOL(net_dev_xmit_hook);

/**
 * Hook for ieee80211 ack i.e. packet sent on wlan
 * eth -> wlan T2
 * wlan -> eth NA
*/
void ieee80211_ack_hook(struct sk_buff *skb)
{
	printk(KERN_DEBUG "ieee80211_ack_hook(%p)\n", skb);
	// Find packet in matching table
	for (int i = 0; i < matchingTableEntryUsed; i++) {
		if (matchingTable[i].skb == skb) {
			// Found packet
			// update T2 if packet direction is eth->wlan
			if (!isLocal(
				    matchingTable[i]
					    .packetDataEntryPtr->flow.src_ip)) {
				matchingTable[i].packetDataEntryPtr->time_sent =
					ktime_get_ns();
				// remove packet from matching table
				matchingTable[i].skb =
					matchingTable[matchingTableEntryUsed - 1]
						.skb;
				matchingTable[i].packetDataEntryPtr =
					matchingTable[matchingTableEntryUsed - 1]
						.packetDataEntryPtr;
				matchingTableEntryUsed--;
			}
			return;
		}
	}
	// packet not found in matching table, ignored
}
EXPORT_SYMBOL(ieee80211_ack_hook);
