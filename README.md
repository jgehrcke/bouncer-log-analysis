A log analysis program, specifically tailored for extracting information from
the log written by Bouncer, the DC/OS identity and access management service.

# Dependencies

Install:

- pandas
- matplotlib


# Usage

```
cat  YOUR_LOG_FILE | python3 bouncer-log-analysis.py --subtitle 'Load test October 10, 2018'
```
