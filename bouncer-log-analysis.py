import logging
import re
import sys
from collections import Counter
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
plt.style.use('ggplot')


logfmt = "%(asctime)s.%(msecs)03d %(name)s %(levelname)s: %(message)s"
datefmt = "%y%m%d-%H:%M:%S"
logging.basicConfig(format=logfmt, datefmt=datefmt, level=logging.INFO)
log = logging.getLogger()


def matplotlib_config():
    matplotlib.rcParams['figure.figsize'] = [10.5, 7.0]
    matplotlib.rcParams['figure.dpi'] = 100
    matplotlib.rcParams['savefig.dpi'] = 150
   #mpl.rcParams['font.size'] = 12


def apache_datestring_to_datetime_obj(s):
    """
    Ref:
    https://github.com/benoitc/gunicorn/blob/master/gunicorn/glogging.py#L333
    """
    return datetime.strptime(s, '%d/%b/%Y:%H:%M:%S %z')


def iso8601_timestamp_to_datetime_obj(s):
    """
    2017-05-17T04:03:05.173862Z

    Ignore the fractional part for now.
    """
    # Split off Z in case of e.g. `2017-05-16T22:37:56Z`
    s = s[:-1].split('.')[0]
    try:
        return datetime.strptime(s, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        print(s)


class Matcher:

    def __init__(self, description):
        self.description = description

    def __repr__(self):
        return '<%s(%r)>' % (self.__class__.__name__, self.description)


class RegexLineMatcher(Matcher):

    _pattern = None

    def match(self, line, linenumber):
        """Save input line number upon match."""
        rm = re.match(self._pattern, line)
        if rm is None:
            return None

        # Construct abstract match object from `re` match object.
        m = self._matchobj(rm)
        m._linenumber = linenumber
        return m


class RequestLogLineMatch:

    __slots__ = [
        '_linenumber',
        'url',
        'status_code',
        'body_size',
        'user_agent',
        'duration_seconds',
        'request_date'
        ]


class RequestLogLineMatcher(RegexLineMatcher):

    # That is the legacy pattern.
    # _pattern_tpl = (
    #     '.+? \[(?P<request_date>.+?)\] '
    #     '"(GET|POST|PUT|DELETE|HEAD) (?P<url>%(urlprefix)s.+?) HTTP/1\..+" '
    #     '(?P<status_code>[0-9]{3}) (?P<body_size>[0-9]+).*?'
    #     '"(?P<user_agent>.*)" \((?P<duration_seconds>.+?) s\)$'
    #     )

    _pattern_tpl = (
        '.+? \[(?P<request_date>[^[]+?)\] '
        '"(GET|POST|PUT|DELETE|HEAD) (?P<url>%(urlprefix)s.*?) HTTP/1\.(0|1)" '
        '(?P<status_code>[0-9]{3}) (?P<body_size>[0-9]+).+?'
        '"(?P<user_agent>.*)" \((?P<duration_seconds>.+?) s\)$'
        )

    def __init__(self, urlprefix="", **kwargs):
        # Escape re meta chars in URL prefix and insert prefix in pattern
        # template.
        super().__init__(**kwargs)
        urlprefix_re = re.escape(urlprefix)
        self._pattern = self._pattern_tpl % {'urlprefix': urlprefix_re}
        log.info('%s pattern: %s', self, self._pattern)

    def _matchobj(self, rm):
        """
        Args:
            rm: regex match object.

        Return:
            Abstract match object adjusted to purpose.
        """
        m = RequestLogLineMatch()
        m.url = rm.group('url')
        #m.status_code = int(rm.group('status_code'))
        m.body_size = int(rm.group('body_size'))
        #m.user_agent = rm.group('user_agent')
        m.duration_seconds = float(rm.group('duration_seconds'))
        m.request_date = apache_datestring_to_datetime_obj(
            rm.group('request_date'))
        return m


class AuditLogLineMatch:

    __slots__ = [
        '_linenumber',
        'timestap_iso8601',
        'srcip',
        'uid',
        'action',
        'object',
        'reason',
        'thread_id',
        'process_id',
        'request_date'
        ]


class AuditLogLineMatcher(RegexLineMatcher):

    _pattern_tpl = (
        '.+? \[(?P<request_date>[^[]+?)\] '
        '\[(?P<process_id>[0-9]+?):(?P<thread_id>.+?)\] .*'
        '\[bouncer.app.internal.PolicyQuery\] INFO: type=audit '
        'timestamp=(?P<timestamp_iso8601>.+?) '
        'srcip=(?P<src_ip>.+?) authorizer=bouncer uid=(?P<uid>.+?) '
        'action=(?P<action>.+?) object=(?P<object>.+?) result=(?P<result>.+?) '
        'reason="(?P<reason>.+?)"'
        )

    def __init__(self):
        # Escape re meta chars in URL prefix and insert prefix in pattern
        # template.
        super().__init__(description="Audit log lines")
        #urlprefix_re = re.escape(urlprefix)
        #self._pattern = self._pattern_tpl % {'urlprefix': urlprefix_re}
        #log.info('%s pattern: %s', self, self._pattern)
        self._pattern = self._pattern_tpl

    def _matchobj(self, rm):
        """
        Args:
            rm: regex match object.

        Return:
            Abstract match object adjusted to purpose.
        """
        m = AuditLogLineMatch()
        m.uid = rm.group('uid')
        m.reason = rm.group('reason')
        m.object = rm.group('object')
        m.action = rm.group('action')
        m.process_id = int(rm.group('process_id'))
        m.thread_id = rm.group('thread_id')
        m.request_date = iso8601_timestamp_to_datetime_obj(
            rm.group('timestamp_iso8601'))
        return m


def main():

    matchers = [
        RequestLogLineMatcher(
            description='Response-acking lines (all requests)'),
        RequestLogLineMatcher(
            urlprefix='/acs/api/v1/internal',
            description='Response-acking lines (requests to /internal)'
            ),
        RequestLogLineMatcher(
            urlprefix='/acs/api/v1/auth/login',
            description='Response-acking lines (Requests to /auth/login)'
            ),
        AuditLogLineMatcher()
        ]


    log.info('Read input lines from stdin')
    input_lines = list(sys.stdin)
    log.info('Number of input lines: %s', len(input_lines))

    matplotlib_config()

    for matcher in matchers:
        log.info('Parse input lines via %s', matcher)
        matches_gen = (matcher.match(l, i+1) for i, l in enumerate(input_lines))
        matches = [m for m in matches_gen if m is not None]
        log.info('Number of matches: %s', len(matches))
        if not matches:
            continue
        analyze_matches(matcher, matches)

    plt.show()


def analyze_matches(matcher, matches):

    if not matches:
        log.info('No matches to analyze')
        return

    log.info('Analyzing matches.')

    # `df.rolling(time_offset)` requires the time index to be monotonic.
    # However, during sane system time updates the logged request date might go
    # backwards. Detect such backwards time jumps and attempt to correct for
    # them.
    log.info('Check increasing monotonicity of time index')
    time_monotonicity_tolerance = timedelta(seconds=2)
    for i, m in enumerate(matches[1:]):
        m_previous = matches[i]
        if m.request_date < m_previous.request_date:
            delta = m_previous.request_date - m.request_date
            log.info(
                'log not monotonic at log line number %s (delta: %s)',
                m._linenumber,
                delta
                )
            if delta < time_monotonicity_tolerance:
                log.info('Add delta(%s) to match timestamp', delta)
                m.request_date = m.request_date + delta

    # Build pandas DataFrame from match objects.
    log.info('Build main DataFrame')

    props_dict = {}

    if isinstance(matches[0], RequestLogLineMatch):
        props_dict['duration_seconds'] = [m.duration_seconds for m in matches]

    if isinstance(matches[0], AuditLogLineMatch):
        props_dict['object'] = [m.object for m in matches]

    df = pd.DataFrame(
        props_dict,
        index=[pd.Timestamp(m.request_date) for m in matches]
        )

    # Bigger gaps and discontinuities in time can have tolerable or intolerable
    # root causes. Only a human can decide. Let's tolerate them here, and just
    # blindly sort samples by time.
    log.info('Sort time index')
    SORT_LOG_LINES_BY_TIME = True
    if SORT_LOG_LINES_BY_TIME:
        df.sort_index(inplace=True)

    starttime = matches[0].request_date
    log.info('Starttime with tz: %s', starttime)
    if starttime.tzinfo:
        local_starttime = (starttime - starttime.utcoffset()).replace(tzinfo=None)
        log.info('Starttime (local time): %s', local_starttime)

    timespan = matches[-1].request_date - matches[0].request_date
    log.info('Time span: %r', pretty_timedelta(timespan))

    log.info('Show top N items for current matcher')

    if isinstance(matches[0], AuditLogLineMatch):
        events = (m.object for m in matches)

    if isinstance(matches[0], RequestLogLineMatch):
        # Build and print top N of most frequently accessed URLs.
        events = (m.url for m in matches)

    counter = Counter(events)
    for label, count in counter.most_common(10):
        percent = int(count / float(len(matches)) * 100)
        print('{:>8} ({:>3} %): {}'.format(count, percent, label))

    plot_rolling_request_rate(df, matcher)

    if isinstance(matches[0], RequestLogLineMatch):
        # Plot request duration histogram only for request log lines.
        plot_request_duration_histogram(df, matcher)


def plot_request_duration_histogram(df, matcher):

    log.info('Plot request duration histogram')
    plt.figure()
    hist, bins = np.histogram(df['duration_seconds'], bins=100)
    width = 0.7 * (bins[1] - bins[0])
    center = (bins[:-1] + bins[1:]) / 2
    plt.bar(
        center,
        hist,
        align='center',
        width=width,
        alpha=0.5
        )
    plt.yscale('symlog')
    plt.xlabel('Request duration [s]')
    plt.ylabel('Number of events')
    plt.title(matcher.description)
    plt.tight_layout(rect=(0,0,1,0.98))

    # Logarithmic view makes a lot of sense, that seems to be nice.
    # Should also find a way to have a clear visualization for a _single_ event
    # which is 10^0 i.e. 0 i.e. a bar with height 0 in the default bar
    # representation, which swallows the data point.
    # symlog seems to do exactly this.


def plot_rolling_request_rate(df, matcher):

    # Do not care about event time, process time series in firstm column.
    rolling_request_rate, df_dft, df_dft_periods = calc_rolling_request_rate(
        df.iloc[:, 0],
        window_width_seconds=2
        )

    if not len(rolling_request_rate):
        log.info('rolling request rate analysis: not enough data')
        return

    plt.figure()

    log.info('Plot request rate over (narrow) rolling window')

    ax = rolling_request_rate.plot(
        linestyle='dashdot',
        #linestyle='None',
        marker='.',
        markersize=0.8,
        markeredgecolor='gray'
        )

    ax.set_xlabel('Local time')
    ax.set_ylabel('Rolling window average request rate [Hz]')

    # Do not care about event time, process time series in firstm column.
    smooth_rolling_request_rate, _ , _ = calc_rolling_request_rate(
        df.iloc[:, 0],
        window_width_seconds=60
        )

    log.info('Plot request rate over (wide) rolling window')
    try:
        ax2 = smooth_rolling_request_rate.plot(
            linestyle='dashdot',
            #linestyle='None',
            marker='.',
            color='black',
            markersize=0.8,
            ax=ax
            )
    except TypeError as e:
        if 'no numeric data to plot' not in str(e):
            raise
        log.info('rolling request rate: not enough data for the smooth curve')

    # The legend story is shitty with pandas intertwined w/ mpl.
    # http://stackoverflow.com/a/30666612/145400
    ax.legend(['2 s window', '60 s window'], numpoints=4)
    ax.set_title(matcher.description)

    # https://matplotlib.org/users/tight_layout_guide.html
    # Use tight_layout?
   #figure = ax.get_figure()
    plt.tight_layout(rect=(0,0,1,0.95))

    filename = 'analysis-%s.pdf' % (
        re.sub('[^A-Za-z0-9]+', '-', matcher.description).lower())

    log.info('Writing PDF figure to %s', filename)
    plt.savefig(filename)


    #plt.figure()
    log.info('Plot freq spec from request rate over narrow rolling window')

    df_dft.plot(
        linestyle='dashdot',
        #linestyle='None',
        marker='.',
        color='black',
        markersize=5,
    )
    plt.xlabel('Frequency [1/s]')
    plt.ylabel('Amplitude')
    set_title(matcher.description)
    set_subtitle('Freq spec from narrow rolling request rate -- mixed load test 180614')
    plt.tight_layout(rect=(0,0,1,0.95))

    # The frequency vector f can be transformed into a period vector p
    # by inverting it: p = 1/f


    # Showing the frequency axis as periudicity axis by
    # just changing the tick labels is a hack that does not
    # allow for properly zooming into the data (in interactive
    # graph viewing).
    # df_dft.plot(
    #     linestyle='dashdot',
    #     #linestyle='None',
    #     marker='.',
    #     color='black',
    #     markersize=5,
    # )
    # plt.xlabel('Period [s]')
    # plt.ylabel('Amplitude')
    # ax = plt.gca()
    # ax.set_xticklabels(periods)

    # Plot the spectrum over "period" instead of time.

    #df_dft.index = periods
    # df_dft.plot(
    #     linestyle='dashdot',
    #     #linestyle='None',
    #     marker='.',
    #     color='black',
    #     markersize=5,
    # )
    # plt.xlabel('Period [s]')
    # plt.ylabel('Amplitude')
    # plt.xlim(15000, 0)  # decreasing time

    ax = df_dft_periods.plot(
        linestyle='dashdot',
        #linestyle='None',
        marker='.',
        color='black',
        markersize=5,
    )
    plt.xlabel('Period [s]')
    plt.ylabel('Amplitude')
    ax.set_xscale('log')
    set_title(matcher.description)
    set_subtitle('Freq spec from narrow rolling request rate -- mixed load test 180614')
    plt.tight_layout(rect=(0,0,1,0.95))


def calc_rolling_request_rate(series, window_width_seconds):
    """
    Require that Series index is a timestamp index.

    http://pandas.pydata.org/pandas-docs/version/0.19.2/api.html#window
    """
    assert isinstance(window_width_seconds, int)

    log.info(
        'Calculate request rate over rolling window (width: %s s)',
        window_width_seconds
        )

    # Example series:
    # 2017-03-08 17:37:19+00:00    0.000350
    # 2017-03-08 17:37:20+00:00    0.000377
    # 2017-03-08 17:37:20+00:00    0.000704
    # 2017-03-08 17:37:20+00:00    0.001263
    # 2017-03-08 17:37:20+00:00    0.000719

    # Each sample/item in the series corresponds to one event. The index value
    # is the datetime of the event, with a resolution of 1 second. Multiple
    # events per second are expected. Get the number of events for any given
    # seconds (group by index value, and get the group size for each unique
    # index value).
    e = series.groupby(series.index).size()

    # New state:
    # 2017-03-08 17:37:19+00:00     1
    # 2017-03-08 17:37:20+00:00    23
    # 2017-03-08 17:37:21+00:00    24
    # 2017-03-08 17:37:22+00:00    49
    # 2017-03-08 17:37:23+00:00     3
    # 2017-03-08 17:37:50+00:00    30

    # The resulting time index is expected to have gaps (where no events occur
    # in a time interval larger than a second), Up-sample the time index to fill
    # these gaps, with 1s resolution and fill the missing values with zeros.
    eventcountseries = e.asfreq('1S', fill_value=0)

    # Construct Window object using `df.rolling()` whereas a time offset string
    # defines the rolling window width in seconds.
    window = eventcountseries.rolling(
        window='%sS' % window_width_seconds,
        min_periods=0
        )

    # Count the number of events (requests) within the rolling window.
    s = window.sum()

    # Normalize event count with/by the window width, yielding the average
    # request rate [Hz] in that time window.
    rolling_request_rate = s / float(window_width_seconds)

    new_rate_column_name = 'request_rate_hz_%ss_window' % window_width_seconds
    rolling_request_rate.rename(new_rate_column_name, inplace=True)

    # In the resulting Series object, the request rate value is assigned to the
    # right window boundary index value (i.e. to the newest timestamp in the
    # window). For presentation it is more convenient to have it assigned
    # (approximately) to the temporal center of the time window. That makes
    # sense for intuitive data interpretation of a single rolling window time
    # series, but is essential for meaningful presentation of multiple rolling
    # window series in the same plot (when their window width varies). Invoking
    # `rolling(..., center=True)` however yields `NotImplementedError: center is
    # not implemented for datetimelike and offset based windows`. As a
    # workaround, shift the data by half the window size to 'the left': shift
    # the timestamp index by a constant / offset.
    offset = pd.DateOffset(seconds=window_width_seconds / 2.0)
    rolling_request_rate.index = rolling_request_rate.index - offset

    # In the resulting time series, all leftmost values up to the rolling window
    # width are dominated by the effect that the rolling window (incoming from
    # the left) does not yet completely overlap with the data. That is, here the
    # rolling window result is (linearly increasing) systematically to small.
    # Because by now the time series has one sample per second, the number of
    # leftmost samples with a bad result corresponds to the window width in
    # seconds. Return just the slice `[window_width_seconds:]`.
    # TODO: also strip off the right bit
    rolling_request_rate = rolling_request_rate[window_width_seconds:]

    # Analyze data using a DFT, for revealing periodically occurring events.
    # Base frequency for signal generation: 1 Hz. The signal are the sample
    # values of the rolling request rate time series.
    signal = rolling_request_rate.values

    # The sampling frequency is 1 Hz.
    f_sample = 1
    # Length of DFT input and output.
    N = len(signal)

    # The frequency delta between data points in the DFT output.
    df = f_sample / N

    # Build frequency vector for DFT output interpretation.
    freqs = np.arange(0, f_sample, df)

    # Get amplitude spectrum through proper normalization (normalization
    # determined based on sampling a simple linear combination of harmonics plus
    # offset).
    amplitudes = 2 * np.abs(np.fft.fft(signal)) / N
    amplitudes[0] = amplitudes[0]/2

    # For a DFT of a truly periodic signal we would not want the data for
    # frequencies larger than the Nyquist frequency (0.5 Hz for 1 Hz sampling
    # rate) and slice at int(np.floor(N/2.0+1)). Here, we want to see much less,
    # because:
    #   - while the sampling rate is 1 second, we know that the samples stem
    #     from averaging with a rolling window of larger width. That is, only
    #     the values for frequencies significantly smaller than the Nyquist
    #     frequency of 0.5 Hz. The values between 0 Hz and 0.1 Hz seem to be
    #     more trustworthy.
    #
    #   - we are actually interested in seeing events that occur every 10 seconds or
    #     much less frequent (such as every 10 minutes).
    #
    # Select a frequency window of 0 Hz to 1/5 Hz for these reasons.
    freq_rlimit = 1/5.0

    # Find the index that has a value closest to `freq_rlimit`.
    idx_rlimit = (np.abs(freqs - freq_rlimit)).argmin()

    amplitudes_selection = amplitudes[0:idx_rlimit]
    freqs_selection = freqs[0:idx_rlimit]

    df_dft = pd.DataFrame(
        data={
            'amplitudes': amplitudes_selection
        },
        index=freqs_selection
    )

    # Create a view of amplitudes over period (s) instead of over frequency
    # (1/s). The first value in `freqs_selection` is zero. float64 division by
    # zero sets special value inf. Invert the frequency values.
    periods = np.float64(1.0) / freqs_selection
    # `periods` looks for example like this:
    # [  inf 2912.  1456.  970.66666667  728 .... 5.01204819 ]
    # Remove the inf value, and reverse the view on the rest.
    periods = np.flipud(periods[1:])
    amplitudes_selection = np.flipud(amplitudes_selection[1:])

    df_dft_periods = pd.DataFrame(
        data={
            'amplitudes': amplitudes_selection
        },
        index=periods
    )

    return rolling_request_rate, df_dft, df_dft_periods


def set_title(text):
    fig = plt.gcf()
    fig.text(
        0.5, 0.98,
        text,
        verticalalignment='center',
        horizontalalignment='center',
        fontsize=14
    )


def set_subtitle(text):
    fig = plt.gcf()
    fig.text(
        0.5, 0.95,
        text,
        verticalalignment='center',
        horizontalalignment='center',
        fontsize=10,
        color='gray'
    )


def pretty_timedelta(timedelta):
    seconds = int(timedelta.total_seconds())
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days > 0:
        return '%dd%dh%dm%ds' % (days, hours, minutes, seconds)
    elif hours > 0:
        return '%dh%dm%ds' % (hours, minutes, seconds)
    elif minutes > 0:
        return '%dm%ds' % (minutes, seconds)
    else:
        return '%ds' % (seconds,)


if __name__ == "__main__":
    main()
