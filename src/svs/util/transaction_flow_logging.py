from datetime import datetime
import logging
logger = logging.getLogger('transaction_flow')

def transaction_log(state, order, component, type, location, status, to = '', frm = '', description = '', root_cause = ''):
    id = state.state_dict.get("SESSION_ID", "n/a")
    try:
        requester = state.state_dict["SATOSA_BASE"]['requester']
    except:
        requester = 'n/a'

    log_entry = dict([('id', id),
                      ('requester', requester),
                      ('component', component),
                      ('type', type),
                      ('location', location),
                      ('status', status),
                      ('frm', frm or ''),
                      ('to', to or ''),
                      ('description', description or ''),
                      ('root_cause', root_cause or ''),
                      ('timestamp', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]),
                ])
    logger.info('%s::%s::%s' % (id, order, log_entry))
