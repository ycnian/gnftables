#ifndef NFTABLES_GUI_DATACHECK_H
#define NFTABLES_GUI_DATACHECK_H




struct transport_data {
	struct {
		int	sport;
		int	dport;
	}tcp;
	struct {
		int	sport;
		int	dport;
	}udp;
};

struct header {
	char	saddr[4];
	char	daddr[4];
	int	transport;
	struct transport_data	*transport_data;
};

struct meta {
	char	*iifname;
	char	*oifname;
	int	iiftype;
	int	oiftype;
	int	skuid;
	int	skgid;
};

struct rule_create_data {
	int		family;
	char		*table;
	char		*chain;
	struct header	*header;
	struct meta	*meta;
};


#endif
