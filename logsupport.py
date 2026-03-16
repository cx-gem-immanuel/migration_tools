import logging  

def setup_logger(name='cxlogger', log_file='main.log', level=logging.DEBUG, enable_console=True, format_log=True):  
    
    logger = logging.getLogger(name)  
    logger.setLevel(level)  
    
    # Create file handler  
    file_handler = logging.FileHandler(log_file)  
    file_handler.setLevel(level)  
    
    if (enable_console):
        # Create console handler  
        console_handler = logging.StreamHandler()  
        console_handler.setLevel(level)
    
    # Create a formatter and set it for handlers  
    if (format_log):
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')  
        file_handler.setFormatter(formatter)  
        if (enable_console):
            console_handler.setFormatter(formatter)  
    
    # Add handlers to the logger  
    if not logger.handlers:  # Prevent adding multiple handlers if setup_logger is called again  
        logger.addHandler(file_handler)  
        if (enable_console):
            logger.addHandler(console_handler)  
    
    return logger  

# Optionally, configure the logger when logsupport is imported  
logger = setup_logger()