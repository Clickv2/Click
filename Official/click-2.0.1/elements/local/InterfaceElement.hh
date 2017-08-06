#ifndef CLICK_SOCKETELEMENT_HH
#define CLICK_SOCKETELEMENT_HH

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>
#include <click/ipaddress.hh>
#include <click/timer.hh>

#include <limits.h>


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
class InterfaceElement;

class interface_record{
public:
	interface_record(struct in_addr multicastAddress, filter_mode FilterMode, Vector<struct in_addr> *sourcelist);
	struct in_addr multicastAddress;
	filter_mode FilterMode;
	Vector<struct in_addr> *sourcelist;
};

//////////////////////////////////////////////////
// Mechanism to schedule/manage reports         //
//////////////////////////////////////////////////

struct scheduledStateChangeReportData {
	// Holds data AND schedules statechange reports
	scheduledStateChangeReportData(unsigned int _amount, unsigned int _interval, in_addr _multicastAddress, unsigned int _filterMode, InterfaceElement* _parentInterface, bool immediateSend = true);

	void addReport(unsigned int _amount, unsigned int _interval, in_addr _multicastAddress, unsigned int _filterMode);
	void sendPacket(bool scheduleOnly = false);

	unsigned int amount;
	unsigned int sent;
	unsigned int interval;

	Vector<in_addr>	multicastAddresses;
	Vector<unsigned int> filterModes;

	InterfaceElement* parentInterface;
	Timer* reportTimer;
};

struct QueryReportScheduler {
	QueryReportScheduler(unsigned int _interval, InterfaceElement* _parentInterface);

	void addReport(unsigned int _interval, String _multicastAddress);

	unsigned int interval;

	Vector<String>	multicastAddresses;
	Vector<Timer*> reportTimers;

	InterfaceElement* parentInterface;
};

struct QueryReportData {
	QueryReportData(QueryReportScheduler* _scheduler, String _multicastAddress) {scheduler = _scheduler; multicastAddress = _multicastAddress;}

	QueryReportScheduler* scheduler;
	String multicastAddress;
};

void run_stateChangeReportData_timer(Timer* timer, void* reportData);
void run_queryResponse_timer(Timer* timer, void* reportData);


class InterfaceElement: public Element{
//output 0 if mine, 1 if i send message, if not mine, nothing is pushed anywhere
public:
	int configure(Vector<String> &, ErrorHandler *);
	InterfaceElement();
	~InterfaceElement();
	const char* class_name() const{return "InterfaceElement";}
	const char* port_count() const{return "1/2";}
	const char* processing() const{return PUSH;}
	void add_handlers();
	static int Leave(const String &conf, Element *e, void* thunk, ErrorHandler *errh);
	static int Join(const String &conf, Element *e, void* thunk, ErrorHandler *errh);
	static int QuietLeave(const String &conf, Element *e, void* thunk, ErrorHandler *errh);
	static int Verbose(const String &conf, Element *e, void* thunk, ErrorHandler *errh);
	static int Silent(const String &conf, Element *e, void* thunk, ErrorHandler *errh);
	void push(int, Packet*); 

	void Reply_to_query();
	void pushReply(Packet *p, int output);

	int robustness_Var;
	int unsolicited_response_interval;

	bool makeOutput;
	int myID;

	static int nextID;

private:
	Vector<interface_record*> state;

	int Query_response_interval;

	scheduledStateChangeReportData stateChangeReports;
	QueryReportScheduler generalQueryReports;

	friend void run_queryResponse_timer(Timer* timer, void* reportData);
	friend class QueryReportScheduler;

};

int _decoder(int resp_or_interval);
int _encoder(int to_encode);

CLICK_ENDDECLS

#endif
