import logging
import re
import sys
from collections import Counter
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
plt.style.use('ggplot')


logfmt = "%(asctime)s.%(msecs)03d %(name)s %(levelname)s: %(message)s"
datefmt = "%y%m%d-%H:%M:%S"
logging.basicConfig(format=logfmt, datefmt=datefmt, level=logging.INFO)
log = logging.getLogger()


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
        '.+? \[(?P<request_date>.+?)\] '
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
        '.+? \[(?P<request_date>.+?)\] '
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

    # Expect that all event types (matches) have a `request_date` set.
    # Not all event types have a duration associated.
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

    # Logarithmic view makes a lot of sense, that seems to be nice.
    # Should also find a way to have a clear visualization for a _single_ event
    # which is 10^0 i.e. 0 i.e. a bar with height 0 in the default bar
    # representation, which swallows the data point.
    # symlog seems to do exactly this.


def plot_rolling_request_rate(df, matcher):

    # Do not care about event time, process time series in firstm column.
    rolling_request_rate = calc_rolling_request_rate(
        df.iloc[:, 0],
        window_width_seconds=3
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
    smooth_rolling_request_rate = calc_rolling_request_rate(
        df.iloc[:, 0],
        window_width_seconds=150
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
    ax.legend(['3 s window', '150 s window'], numpoints=4)
    ax.set_title(matcher.description)
    figure = ax.get_figure()

    filename = 'analysis-%s.pdf' % (
        re.sub('[^A-Za-z0-9]+', '-', matcher.description).lower())

    log.info('Writing PDF figure to %s', filename)
    plt.savefig(filename)


# Make a nice Fourier analysis

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
    eventcountseries = e.resample('1S').asfreq().fillna(0)

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
    return rolling_request_rate[window_width_seconds:]


if __name__ == "__main__":
    main()
