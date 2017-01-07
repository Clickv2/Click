#ifndef CLICK_ROUTERINTERFACECONNECTOR_HH
#define CLICK_ROUTERINTERFACECONNECTOR_HH

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>
#include "GroupRecordGenerator.hh"




CLICK_DECLS

class RouterInterface;

class RouterInterfaceConnector: public Element{
public:
	/// Connects the interfaces so that a router may respond to queries
	int configure(Vector<String> &, ErrorHandler *);
	RouterInterfaceConnector();
	~RouterInterfaceConnector();
	const char* class_name() const{return "RouterInterfaceConnector";}
	const char* port_count() const{return "0/0";}
	const char* processing() const{return PUSH;}

	void logonElement(RouterInterface* interface);
		/// Registers the interface of the router so that others may get info from him

	GroupReportGenerator getQueryResponse();

	Vector<RouterInterface*> f_interfaces;
};

CLICK_ENDDECLS

#endif
