import threading
import sys
import os
import time

def query_by_id(user_id):
    print('123')

def query_by_name(user_name):
    print('234')

class suppress_stdout_stderr(object):
    '''
    A context manager for doing a "deep suppression" of stdout and stderr in
    Python, i.e. will suppress all print, even if the print originates in a
    compiled C/Fortran sub-function.
       This will not suppress raised exceptions, since exceptions are printed
    to stderr just before a script exits, and after the context manager has
    exited (at least, I think that is why it lets exceptions through).

    '''
    def __init__(self):
        # Open a pair of null files
        self.null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
        # Save the actual stdout (1) and stderr (2) file descriptors.
        self.save_fds = (os.dup(1), os.dup(2))

    def __enter__(self):
        # Assign the null pointers to stdout and stderr.
        os.dup2(self.null_fds[0], 1)
        os.dup2(self.null_fds[1], 2)

    def __exit__(self, *_):
        # Re-assign the real stdout/stderr back to (1) and (2)
        os.dup2(self.save_fds[0], 1)
        os.dup2(self.save_fds[1], 2)
        # Close the null files
        os.close(self.null_fds[0])
        os.close(self.null_fds[1])


class Controller(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)


    def run(self):
        #sys.stdout = open(os.devnull, 'w')
        
        while(True):
            time.sleep(2)
            print("Controller")
      
            
    def stop():
        threading.Thread._stop()


class Controller1(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)


    def run(self):
        while(True):
            time.sleep(2)
            print("Controller1")
      
            
    def stop():
        threading.Thread._stop()


def main():
    
    a=Controller()
    b=Controller1()
   
    a.start()
    b.start()

    while(True):
        print(1)
        cmd=raw_input("cmd:")
        print(cmd)




if __name__ == '__main__':
    main()
