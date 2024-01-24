#if !defined(NET__FLOW_ANALYSIS_TRACING_H)
#define NET__FLOW_ANALYSIS_TRACING_H

struct sk_buff;

void netif_receive_skb_hook(struct sk_buff* skb);
void net_dev_xmit_hook(struct sk_buff* skb);
void ieee80211_xmit_hook(struct sk_buff* skb);
void ieee80211_ack_hook(struct sk_buff* skb);


#endif // NET__FLOW_ANALYSIS_TRACING_H
