#ifndef CLICK_GROUPRECORDGENERATOR_HH
#define CLICK_GROUPRECORDGENERATOR_HH

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>

#include "GroupRecord.hh"


CLICK_DECLS


class GroupRecordGenerator{
public:
	GroupRecordGenerator();
	~GroupRecordGenerator();

	bool initNewRecord(uint8_t recordType, uint8_t auxDataLen, uint16_t nrOfSources, click_ip multicastAddress);
		/// Since we work with a vector, the number of sources isn't actually needed
		/// BUT the size of the vector can be greater than the size of an uint16_t
		/// I'm sure you can easily check for that, but this way had the most advantages
	bool addSourceAddress(click_ip unicastAddress);

	GroupRecord* getCurrentRecord() const;
		/// Note: this returns a copy of the current made record
		/// This grouprecord is now responsible for deleting itself properly
		/// returns a nullpointer if the current record would be invalid

	bool setRecordType(int8_t recordType);
private:
	void flushPreviousRecord();

	uint8_t f_recordType;
	uint8_t f_auxDataLen;
	uint16_t f_nrOfSources;
	click_ip f_multicastAddress;
	Vector<click_ip> f_sourceList;

	uint16_t f_addressesGiven;
	bool f_makingRecord;
};

CLICK_ENDDECLS

#endif