#ifndef CLICK_ROUTERINTERFACE_HH
#define CLICK_ROUTERINTERFACE_HH

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>
#include "RouterInterfaceConnector.hh"

CLICK_DECLS

class RouterRecord;
class PacketScheduler;

class RouterInterface: public Element{
	/// Set IGMP queries on output 0, set IGMP packets on output 1 and other IP stuff on output 2
public:
	RouterInterface();
	~RouterInterface();
	
	const char *class_name() const	{ return "RouterInterface"; }
	const char *port_count() const	{ return "1/4"; }
	const char *processing() const	{ return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);
	
	///void run_timer(Timer *);

	///static int configureSettings(const String &conf, Element *e, void * thunk, ErrorHandler * errh);
	// static String getSettings(Element *e, void * thunk);
	// void add_handlers();

	void deleteRecord(RouterRecord* record);
	void deleteScheduler(PacketScheduler* scheduler);
	void push(int, Packet*);

public:

	void querierElection(Packet* p);

	void interpretGroupReport(Packet* p);
	void sendSpecificQuery(IPAddress multicastAddress);
	void updateInterface(Vector<IPAddress>& toListen, Vector<IPAddress>& toQuery);

	void add_handlers();
	static int TakeOverQuery(const String &conf, Element *e, void* thunk, ErrorHandler *errh);
	static int PassiveQuery(const String &conf, Element *e, void* thunk, ErrorHandler *errh);

	/// TODO fix maxrespcode => code and time are used across each other
	uint8_t f_maximumMaxRespCode;
	bool f_SFlag;
	uint8_t f_QRV;
	uint8_t f_QQIC;
	IPAddress f_myIP;
	unsigned int f_queryInterval;
		/// Send general query every x seconds
	unsigned int f_queryResponseInterval;
		/// divide by 10 = seconds
		/// MaxResp time for general queries
	double f_groupMembershipInterval;
		/// Timer timeout => group has no members

	double f_otherQuerierPresentInterval;
		/// Must be QRV * QI + QRI / 2
	double f_startupQueryInterval;
		/// 1/4 QI
	double f_startupQueryCount;
		/// # queries sent on startup seperated by the above interval
		/// default = QRV


	unsigned int f_lastMemberQueryCount;
		/// amt of group-specific queries sent before the router assumes there are no members
	unsigned int f_lastMemberQueryTime;
		/// see rfc
	unsigned int f_lastMemberQueryInterval;
		/// maxresp time used to calc the maxrespcode in group-specific queries


	Vector<RouterRecord> f_state;
	Vector<PacketScheduler*> f_schedulers;

	RouterInterfaceConnector* f_interfaceConnector;
};

class RouterRecord{
public:
	RouterRecord(IPAddress ip, uint8_t filterMode, double timeOut, Element* parentInterface);
		/// Note that everything is assumed to be correct
	~RouterRecord();

	void refreshInterest();

	bool operator==(RouterRecord& otherRecord);

	IPAddress f_ip;
	Timer* f_groupTimer;
	uint8_t f_filterMode;
	unsigned int f_timeOut;
	Element* f_parentInterface;

};

void run_timer(Timer* timer, void* routerRecord);


class PacketScheduler{
public:
	PacketScheduler(String multicastAddr, int sendEvery_X_ms, Element* parentInterface, int amountOfTimes, unsigned int outputPort);
	PacketScheduler(GroupReportGenerator gen, int sendEvery_X_ms, Element* parentInterface, int amountOfTimes, unsigned int outputPort);

	~PacketScheduler();

	void sendPacket();

	void suppress(double time, double startupInterval, unsigned int startupCount);

	void reset();

	static unsigned int f_nextID;

	String f_multicastAddr;
	GroupReportGenerator f_gen;
	int f_time;
	Timer* f_timer;
	RouterInterface* f_parentInterface;
	int f_amountOfTimes;
	int f_amountOfTimesSent;
	unsigned int f_outputPort;
	unsigned int f_ID;

	bool f_suppress;
	Timer* f_suppressTimer;
	double f_startupInterval;
	int f_startupCount;
	int f_startupSent;

};

void sendToSchedulerPacket(Timer* timer, void* scheduler);

void startup(Timer* timer, void* scheduler);

CLICK_ENDDECLS

#endif
