'''
START OF LICENSE STUB
    FineLame: Detecting Application-Layer Denial-of-Service Attacks
    Copyright (C) 2019 University of Pennsylvania

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
END OF LICENSE STUB
'''

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

formatter = logging.Formatter('%(levelname)s: %(message)s')
ch.setFormatter(formatter)

logger.addHandler(ch)

def log_error(*args, **kwargs):
    logger.error(*args, **kwargs)

def log_info(*args, **kwargs):
    logger.info(*args, **kwargs)

def log_warn(*args, **kwargs):
    logger.warn(*args, **kwargs)

def log_debug(*args, **kwargs):
    logger.debug(*args, **kwargs)
