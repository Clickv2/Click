#ifndef CLICK_SOCKETELEMENT_HH
#define CLICK_SOCKETELEMENT_HH

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>


#ifndef MODE_IS_INCLUDE
#define MODE_IS_INCLUDE 1
#endif

#ifndef MODE_IS_EXCLUDE
#define MODE_IS_EXCLUDE 2
#endif

#ifndef CHANGE_TO_INCLUDE
#define CHANGE_TO_INCLUDE 3
#endif

#ifndef CHANGE_TO_EXCLUDE
#define CHANGE_TO_EXCLUDE 4
#endif

#ifndef REPORTMESSAGE
#define REPORTMESSAGE 0x22
#endif

#ifndef QUERYMESSAGE
#define QUERYMESSAGE 0x11
#endif

#ifndef SUPPRESS_OUTPUT
#define SUPPRESS_OUTPUT false
#endif

#ifndef REPORTMESSAGE
#define REPORTMESSAGE 0x22
#endif


CLICK_DECLS
enum filter_mode {INCLUDE, EXCLUDE};
enum filter_mode_change {TO_INCLUDE, TO_EXCLUDE};

class interface_record{
public:
	interface_record(struct in_addr multicastAddress, filter_mode FilterMode, Vector<struct in_addr> *sourcelist);
	struct in_addr multicastAddress;
	filter_mode FilterMode;
	Vector<struct in_addr> *sourcelist;
};


class InterfaceElement: public Element{
//output 0 if mine, 1 if i send message, 2 if not mine
public:
	int configure(Vector<String> &, ErrorHandler *);
	InterfaceElement();
	~InterfaceElement();
	void add_handlers();
	static int Leave(const String &conf, Element *e, void* thunk, ErrorHandler *errh);
	static int Join(const String &conf, Element *e, void* thunk, ErrorHandler *errh);
	const char* class_name() const{return "InterfaceElement";}
	const char* port_count() const{return "1/2";}
	const char* processing() const{return PUSH;}
	void push(int, Packet*); 
private:
	Vector<interface_record*> state;
	bool filterchange;
	filter_mode_change change;
	IPAddress interfaceaddress;

};
/*
struct socket_record{
	Interface* interface;
	struct in_addr multicastAddress;
	filter_mode FilterMode;
	Vector<struct in_addr> sourcelist;
};

class SocketElement: public Element{
public:
	SocketElement();
	~SocketElement();
  	void add_handlers();
	int handle(const char* &conf, Element *e, void* thunk, ErrorHandler *errh);
private:
	Vector<socket_record> state;
	bool filterchange;
	filter_mode_change change;

};*/
CLICK_ENDDECLS

#endif
