from datetime import datetime
import logging
logger = logging.getLogger('transaction_flow')

def transaction_log(id, order, component, type, location, status, to = '', frm = '', description = '', root_cause = ''):
    log_entry = dict([('id', id),
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
    
