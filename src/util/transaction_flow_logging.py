from datetime import datetime
import logging
logger = logging.getLogger('transaction_flow')

def transaction_log(id, order, component, type, location, status, description = ''):
    log_entry = dict([('id', id),
                      ('component', component),
                      ('type', type),
                      ('location', location),
                      ('status', status),
                      ('description', description or ''),
                      ('timestamp', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]),
                ])
    logger.info('%s::%s::%s' % (id, order, log_entry))