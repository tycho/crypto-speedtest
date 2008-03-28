// $Id$
// Not really an include file, more a base file for the speed tests.

#include <assert.h>
#include <stdint.h>
#include <sys/time.h>

#include <vector>
#include <map>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <numeric>
#include <cmath>

// *** Speedtest Parameters ***

// speed test different buffer sizes in this range
const unsigned int buffermin = 16;
const unsigned int buffermax = 16 * 65536;
const unsigned int repeatsize = 65536;
const unsigned int minrepeats = 2;
const unsigned int measureruns = 64;

/// Time is measured using gettimeofday()
inline double timestamp()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 0.000001;
}

// *** Global Buffers and Settings for the Speedtest Functions ***

char	enckey[32];	/// 256 bit encryption key
char	enciv[16];	/// 16 byte initialization vector if needed.

char	buffer[buffermax];	/// encryption buffer
unsigned int bufferlen;		/// currently tested buffer length

// *** run_test() ***

/**
 * This function will run a test routine multiple times with different buffer
 * sizes configured. It measures the time required to encrypt a number of
 * bytes. The average time and standard deviation are calculated and written to
 * a log file for gnuplot.
 */

template <void (*testfunc)()>
void run_test(const char* logfile)
{
    std::cout << "Speed testing for " << logfile << "\n";

    // Save the time required for each run.
    std::map<unsigned int, std::vector<double> > timelog;

    for(unsigned int fullrun = 0; fullrun < measureruns; ++fullrun)
    {
	for(unsigned int bufflen = buffermin; bufflen <= buffermax; bufflen *= 2)
	{
	    // because small time measurements are inaccurate, repeat very fast
	    // tests until the same amount of data is encrypted as in the large
	    // tests.
	    unsigned int repeat = repeatsize / bufflen;
	    if (repeat < minrepeats) repeat = minrepeats;

	    // std::cout << "Test: bufflen " << bufflen << " repeat " << repeat << "\n";

	    bufferlen = bufflen;

	    // fill buffer
	    for(unsigned int i = 0; i < bufferlen; ++i)
		buffer[i] = (char)i;

	    double ts1 = timestamp();

	    for(unsigned int testrun = 0; testrun < repeat; ++testrun)
	    {
		testfunc();
	    }

	    double ts2 = timestamp();

	    // check buffer status after repeated en/decryption
	    for(unsigned int i = 0; i < bufferlen; ++i)
		assert(buffer[i] == (char)i);

	    timelog[bufferlen].push_back( (ts2 - ts1) / (double)repeat );
	}
    }

    // Calculate and output statistics.
    std::ofstream of (logfile);

    // First output time absolute measurements
    for(std::map<unsigned int, std::vector<double> >::const_iterator ti = timelog.begin();
	ti != timelog.end(); ++ti)
    {
	const std::vector<double>& timelist = ti->second;

	double average = std::accumulate(timelist.begin(), timelist.end(), 0.0) / timelist.size();

	double variance = 0.0;
	for(unsigned int i = 0; i < timelist.size(); ++i)
	{
	    variance += (timelist[i] - average) * (timelist[i] - average);
	}
	variance = variance / (timelist.size() - 1);

	double stddev = std::sqrt(variance);

	if (timelist.size() == 1) { // only one run -> no variance or stddev
	    variance = stddev = 0.0;
	}

	double vmin = *std::min_element(timelist.begin(), timelist.end());
	double vmax = *std::max_element(timelist.begin(), timelist.end());

	of << std::setprecision(16);
	of << ti->first << " " << average << " " << stddev << " " << vmin << " " << vmax << "\n";
    }
    of << "\n\n";

    // Second output speed measurements
    for(std::map<unsigned int, std::vector<double> >::const_iterator ti = timelog.begin();
	ti != timelog.end(); ++ti)
    {
	const std::vector<double>& timelist = ti->second;

	double average = 0.0;
	double vmin = +INFINITY;
	double vmax = -INFINITY;

	for(unsigned int i = 0; i < timelist.size(); ++i)
	{
	    average += ti->first / timelist[i];
	    vmin = std::min(vmin, (ti->first / timelist[i]));
	    vmax = std::max(vmax, (ti->first / timelist[i]));
	}
	average /= timelist.size();

	double variance = 0.0;
	for(unsigned int i = 0; i < timelist.size(); ++i)
	{
	    double delta = (ti->first / timelist[i]) - average;
	    variance += delta * delta;
	}
	variance = variance / (timelist.size() - 1);

	double stddev = std::sqrt(variance);

	if (timelist.size() == 1) { // only one run -> no variance or stddev
	    variance = stddev = 0.0;
	}

	of << std::setprecision(16);
	of << ti->first << " " << average << " " << stddev << " " << vmin << " " << vmax << "\n";
    }
    of.close();
}
