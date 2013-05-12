import os
import win32file
import win32api
import win32con
import threading
import queue
import time
import shutil
import tempfile
import collections
import hashlib
import winreg

ACTIONS = {
    1 : "create",
    2 : "delete",
    3 : "update",
    4 : "rename",   #from
    5 : "rename"    #to
}

FILE_LIST_DIRECTORY = 0x0001

class StoppableThread(threading.Thread):
    # Quick subclass to make ctrl-c work & close off infinite loops.
    def __init__(self):
        threading.Thread.__init__(self)
        self.stop_event = threading.Event()        

    def stop(self):
        if self.isAlive() == True:
            # set event to signal thread to terminate
            self.stop_event.set()
            # block calling thread until thread really has terminated
            self.join()

class WatcherThread(StoppableThread):

    def __init__(self, eventq, watch_path, blist):
        StoppableThread.__init__(self)
        self.eventq = eventq
        self.path_test = watch_path
        self.blist = blist # queue
        self.hDir = win32file.CreateFile(
            self.path_test,
            FILE_LIST_DIRECTORY,
            win32con.FILE_SHARE_READ |
             win32con.FILE_SHARE_WRITE |
             win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )

    def run(self):
        place = None
        blist = []
        while self.stop_event.is_set() == False:
            #
            # ReadDirectoryChangesW takes a previously-created
            # handle to a directory, a buffer size for results,
            # a flag to indicate whether to watch subtrees and
            # a filter of what changes to notify.
            #
            # NB Tim Juchcinski reports that he needed to up
            # the buffer size to be sure of picking up all
            # events when a large number of files were
            # deleted at once.
            #
            results = win32file.ReadDirectoryChangesW(
                self.hDir,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                 win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                 win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                 win32con.FILE_NOTIFY_CHANGE_SIZE |
                 win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                 win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None
            )
            
            # Maintain changes to in-memory blacklist
            while self.blist.empty() == False:
                bl = self.blist.get()
                if bl[0] == 1:
                    blist.append(bl[1])
                else:
                    blist.remove(bl[1])

            for action, file in results:
                # Messy but necessary
                if bl == file:
                    continue
                if (action == 4) and (place is None):
                    place = file
                    continue
                elif (action == 4) and (place is not None):
                    event = [action + 1, self.path_test, place, file]
                    place = None
                elif (action == 5) and (place is not None):
                    event = [action, self.path_test, file, place]
                    place = None
                elif (action == 5) and (place is None):
                    place = file
                    continue
                else:
                    event = [action, self.path_test, file, None]
                self.eventq.put(event)

class WPollThread(StoppableThread):

    def __init__(self, eventq, watch_path, blist):
        StoppableThread.__init__(self)
        self.eventq = eventq
        self.path_test = watch_path
        self.blist = blist # queue
        self.before = dict ([(f, None) for f in os.listdir (path_to_watch)])
        self.time = time.time()

    def run(self):
        # If polling weren't evil, I'd be quite pleased with this
        # Pity it doesn't handle rename as well as it should, and only
        # keys updates off mtime, but I'll take what I can get.
        place = None
        blist = []
        while self.stop_event.is_set() == False:
            time.sleep(10)
            after = dict([(f, None) for f in os.listdir (path_to_watch)])
            
            while self.blist.empty() == False:
                bl = self.blist.get()
                if bl[0] == 1:
                    blist.append(bl[1])
                else:
                    blist.remove(bl[1])
            added = [f for f in after if not f in before and not f in blist]
            removed = [f for f in before if not f in after and not f in blist]
            updated = [f for f in after if f in before and os.path.getmtime(f) > self.time]
            
            if added:
                # Create event
                for f in added:
                    self.eventq.put([1, self.path_test, f, None])
            if removed:
                # Create event
                for f in removed:
                    self.eventq.put([2, self.path_test, f, None])
            if updated:
                # Create event
                for f in updated:
                    self.eventq.put([3, self.path_test, f, None])
            self.before = after
            self.time = time.time()

class ActorThread(StoppableThread):

    def __init__(self, eventq, sync_dirs, rsync_handle, blists):
        StoppableThread.__init__(self)
        self.eventq = eventq
        self.sync_dirs = sync_dirs
        self.rsync = rsync_handle
        self.blists = blists

    def blist_add(self, file):
        rec = (1, file)
        for q in self.blists:
            q.put(rec)

    def blist_sub(self, file):
        rec = (0, file)
        for q in self.blists:
            q.put(rec)

    def run(self):
        while self.stop_event.is_set() == False:
            event = self.eventq.get(True)
            
            for target in self.sync_dirs:
                # Exclude source dir & unknown events
                if event[1] == target:
                    continue
                if ACTIONS.get(event[0], None) is None:
                    continue
                method = "{}".format(ACTIONS[event[0]])
                msg = "Event out: Trying {0} in {1} from {2}".format(method,
                                                                     target,
                                                                     event[1])
                print(msg)
                result = getattr(self, method)(event, target)
                # FIXME: Do something with result
                # Tempted to add something about time-wait exceptions later
                print(result)
            
            self.eventq.task_done()
    
    def create(self, cevent, target_dir):
        dest_file = os.path.join(target_dir, cevent[2])
        source_file = os.path.join(cevent[1], cevent[2])
        
        # Handle directories
        if os.path.isdir(source_file):
            if source_file.endswith("Conflict]"):
                return "Not copying conflict directory"
            elif os.path.exists(dest_file):
                dest_file += "[{} Conflict]".format(time.ctime())
            try:
                shutil.copytree(source_file, dest_file)
            except:
                return "Copytree failed"
            else:
                return "Directory copied fine"

        # Handle files
        (sr, se) = os.path.splitext(source_file)
        if sr.endswith("Conflict]"):
            # Event triggered because another directory has a conflict; ignore
            return "Not copying conflict file"
        
        if os.path.exists(dest_file):
            # Filename conflict? use os.stat
            s_stat = os.stat(source_file)
            d_stat = os.stat(dest_file)
            
            if (s_stat[6] == d_stat[6]) and (s_stat[8] == d_stat[8]):
                # Size and mtime agree
                return "File already exists"
            else:
                # Append a "Time Conflict" tag to the end of the filename
                (root, ext) = os.path.splitext(dest_file)
                root += "[{} Conflict]".format(time.ctime())
                dest_file = root + ext
        
        try:
            shutil.copy2(source_file, dest_file)
        except (IOError, os.error) as why:
            return str(why)
        except Error as err:
            return str(err.args[0])
        else:
            return "Create succeeded"

    def delete(self, cevent, target_dir):
        trash_file = os.path.join(target_dir, cevent[2])
        
        if not os.path.exists(trash_file):
            return "File already deleted"

        if os.path.isdir(trash_file):
            try:
                shutil.rmtree(trash_file)
            except Error as err:
                return str(err.args[0])
            else:
                return "Directory trashed"

        try:
            os.remove(trash_file)
        except IOError as err:
            err = "Error removing " + trash_file + " File still in use."
            return err
        else:
            return "File trashed"

    def update(self, cevent, target_dir):
        dest_file = os.path.join(target_dir, cevent[2])
        source_file = os.path.join(cevent[1], cevent[2])
        
        # This operation requires a third file (blame PyRsync below)...
        dfh = open(dest_file, "rb")
        sfh = open(source_file, "rb")
        tf = tempfile.TemporaryFile()
        
        hashes = self.rsync.blockchecksums(dfh)
        delta = self.rsync.rsyncdelta(sfh, hashes)
        sfh.close()

        if len(delta) == 1:
            dfh.close()
            return "Nothing to update"

        self.blist_add(cevent[2])
        
        dfh.seek(0)
        self.rsync.patchstream(dfh, tf, delta)
        dfh.close()
        
        tf.seek(0)
        dfh = open(dest_file, "w+b")

        try:
            shutil.copyfileobj(tf, dfh)
        except IOError as err:
            err = "Error removing " + tf + " File still in use."
            out = err
        else:
            out = "File object copied"

        tf.close()
        dfh.close()

        return out

    def rename(self, cevent, target_dir):
        old_name = os.path.join(target_dir, cevent[3])
        new_name = os.path.join(target_dir, cevent[2])
        
        if (not os.path.exists(old_name)) and (os.path.exists(new_name)):
            # Rename's already done here.
            return "File already renamed"
        
        if os.path.exists(new_name) and os.path.exists(old_name):
            # ... I have no idea how we've got here.
            # Screw it. Call the new name a conflict.
            (root, ext) = os.path.splitext(new_name)
            root += "[{} Conflict]".format(time.ctime())
            new_name = root + ext
            
        try:
            shutil.move(old_name, new_name)
        except IOError as err:
            err = "Error moving " + old_name + " File still in use."
            return err
        else:
            return "File renamed"            

class PyRsync(object):
    """
    This is a pure Python implementation of the [rsync algorithm](TM96).

    [TM96] Andrew Tridgell and Paul Mackerras. The rsync algorithm.
    Technical Report TR-CS-96-05, Canberra 0200 ACT, Australia, 1996.
    http://samba.anu.edu.au/rsync/.

    ### Example Use Case: ###

        # On the system containing the file that needs to be patched
        >>> unpatched = open("unpatched.file", "rb")
        >>> hashes = blockchecksums(unpatched)

        # On the remote system after having received `hashes`
        >>> patchedfile = open("patched.file", "rb")
        >>> delta = rsyncdelta(patchedfile, hashes)

        # System with the unpatched file after receiving `delta`
        >>> unpatched.seek(0)
        >>> save_to = open("locally-patched.file", "wb")
        >>> patchstream(unpatched, save_to, delta)
    """

    def __init__(self):
        self.__all__ = ["rollingchecksum", 
                        "weakchecksum", 
                        "patchstream", 
                        "rsyncdelta", 
                        "blockchecksums"]

    def rsyncdelta(self, datastream, remotesignatures, blocksize=4096):
        """
        Generates a binary patch when supplied with the weak and strong
        hashes from an unpatched target and a readable stream for the
        up-to-date data. The blocksize must be the same as the value
        used to generate remotesignatures.
        """
        remote_weak, remote_strong = remotesignatures

        match = True
        matchblock = -1
        deltaqueue = collections.deque()

        while True:
            if match and datastream is not None:
                # Whenever there is a match or the loop is running for the first
                # time, populate the window using weakchecksum instead of rolling
                # through every single byte which takes at least twice as long.
                window = collections.deque(bytes(datastream.read(blocksize)))
                checksum, a, b = self.weakchecksum(window)

            try:
                # If there are two identical weak checksums in a file, and the
                # matching strong hash does not occur at the first match, it will
                # be missed and the data sent over. May fix eventually, but this
                # problem arises very rarely.
                matchblock = remote_weak.index(checksum, matchblock + 1)
                stronghash = hashlib.md5(bytes(window)).hexdigest()
                matchblock = remote_strong.index(stronghash, matchblock)

                match = True
                deltaqueue.append(matchblock)

                if datastream.closed:
                    break
                continue

            except ValueError:
                # The weakchecksum did not match
                match = False
                try:
                    if datastream:
                        # Get the next byte and affix to the window
                        newbyte = ord(datastream.read(1))
                        window.append(newbyte)
                except TypeError:
                    # No more data from the file; the window will slowly shrink.
                    # newbyte needs to be zero from here on to keep the checksum
                    # correct.
                    newbyte = 0
                    tailsize = datastream.tell() % blocksize
                    datastream = None

                if datastream is None and len(window) <= tailsize:
                    # The likelihood that any blocks will match after this is
                    # nearly nil so call it quits.
                    deltaqueue.append(window)
                    break

                # Yank off the extra byte and calculate the new window checksum
                oldbyte = window.popleft()
                checksum, a, b = self.rollingchecksum(oldbyte, newbyte, a, b, blocksize)

                # Add the old byte the file delta. This is data that was not found
                # inside of a matching block so it needs to be sent to the target.
                try:
                    deltaqueue[-1].append(oldbyte)
                except (AttributeError, IndexError):
                    deltaqueue.append([oldbyte])

        # Return a delta that starts with the blocksize and converts all iterables
        # to bytes.
        deltastructure = [blocksize]
        for element in deltaqueue:
            if isinstance(element, int):
                deltastructure.append(element)
            elif element:
                deltastructure.append(bytes(element))

        return deltastructure


    def blockchecksums(self, instream, blocksize=4096):
        """
        Returns a list of weak and strong hashes for each block of the
        defined size for the given data stream.
        """
        weakhashes = list()
        stronghashes = list()
        read = instream.read(blocksize)

        while read:
            weakhashes.append(self.weakchecksum(bytes(read))[0])
            stronghashes.append(hashlib.md5(read).hexdigest())
            read = instream.read(blocksize)

        return weakhashes, stronghashes


    def patchstream(self, instream, outstream, delta):
        """
        Patches instream using the supplied delta and write the resultantant
        data to outstream.
        """
        blocksize = delta[0]

        for element in delta[1:]:
            if isinstance(element, int) and blocksize:
                instream.seek(element * blocksize)
                element = instream.read(blocksize)
            outstream.write(element)


    def rollingchecksum(self, removed, new, a, b, blocksize=4096):
        """
        Generates a new weak checksum when supplied with the internal state
        of the checksum calculation for the previous window, the removed
        byte, and the added byte.
        """
        a -= removed - new
        b -= removed * blocksize - a
        return (b << 16) | a, a, b


    def weakchecksum(self, data):
        """
        Generates a weak checksum from an iterable set of bytes.
        """
        a = b = 0
        l = len(data)
        for i in range(l):
            a += data[i]
            b += (l - i)*data[i]

        return (b << 16) | a, a, b

def main():
    (time, watch_dirs) = read_config()

    r = PyRsync()
    eventq = queue.Queue()
    do_exit = False
    
    # Build list of changes
    actionlist = build_actions(list(watch_dirs.keys()))
    
    for a in actionlist:
        eventq.put(action)

    watchers = []
    watchqueues = []

    for d in watch_dirs:
        wq = queue.Queue()
        if watch_dirs[d] == "0":
            w = WatcherThread(eventq, d, wq)
        else:
            w = WPollThread(eventq, d, wq)
        watchqueues.append(wq)
        w.start()
        watchers.append(w)

    a = ActorThread(eventq, list(watch_dirs.keys()), r, watchqueues)
    a.start()

    while do_exit == False:
        try:
            time.sleep(0.1)
        except KeyboardInterrupt:
            do_exit = True

    for w in watchers:
        w.stop()
    a.stop()
    t_0 = str(time.time())
    write_time(t_0)
    
def build_actions(dirs, time):
    actions = []
    changed = []
    st = []
    conf = {}
    
    # Build manifests of each dir.
    for dir in dirs:
        (c, s) = create_manifests(dir)
        changed.append(c)
        st.append(s)
    
    # Four cases, handled below.
    # 1) file is in manifest & static (update)
    # 2) file is in manifest & manifest (conflicted update)
    # 3) file is in manifest & None (create)
    # 4) File is in None & static (delete)

    ###################
    # CASE 1 / CASE 3 #
    ###################

    # As we're comparing against the other st,
    # use range(len) to get a key in.
    for i in range(len(changed)):
        j = (i+1) % 2
        for m in changed[i]:
            # If case 1, remove from static. 
            # Trust me, this makes finding deletes so much easier ITLR
            if m[0] in st[j]:
                event = [3, dirs[i], m[0], None]
                st[j].remove(m[i])
            # Case 2. We'll deal with conf in a bit.
            elif m[0] in [x[0] for x in m[j]]:
                conf[m[0]][i] = m[0]
            # Case 3
            elif m[0] not in st[j]:
                event = [1, dirs[i], m[0], None]
            # Something's b0rked
            else:
                print("This should never happen, a not in (a union a')")
                pass
            actions.append(event)
    
    ##########
    # CASE 4 #
    ##########
    
    # Remove elements where both files are in static; we don't touch them.
    # Make a master list of [file, directory to delete from]
    to_del = [[x, 1] for x in st[0] if x not in st[1]] 
    to_del += [[x, 0] for x in st[1] if x not in st[0]]
    
    for file in to_del:
        event = [2, dirs[file[1]], file[0], None]
        actions.append(event)
    
    ##########
    # CASE 2 #
    ##########
    
    # Get "left" and "right" dicts where the key is the filename and the value
    # is the file's mtime.
    ldir = dict([(f, os.path.getmtime(f)) for f in changed[0] if os.path.getmtime(f) > time and f in changed[1]])
    rdir = dict([(f, os.path.getmtime(f)) for f in changed[1] if os.path.getmtime(f) > time and f in changed[0]])

    for f in ldir:
        if ldir[f] == rdir[f]:
            # Both updated at same time; probably due to crash/stopped process
            # Skip the file
            continue
        elif ldir[f] > rdir[f]:
            event = [3, dirs[0], f, None]
        else:
            event = [3, dirs[0], f, None]
        actions.append(event)      

def create_manifests(d, time):
    
    changed = []
    unchanged = []
    
    # Format directory and walk it
    # For each file, get its full filename including path
    directory = os.path.normpath(d)
    for dirname, dirnames, filenames in os.walk(directory):
        for files in filenames:
            fn = os.path.normpath(os.path.join(dirname, files))
            
            # Get the name relative to start directory and the mtime.
            # If mtime is newer than the last run time, add it to changed
            # Otherwise add to static.
            name = fn[len(nodeman["path"])+1:]
            mtime = os.path.getmtime(fn)
            if mtime > time:
                changed.append([name, time])
            else:
                static.append(name)
    return (changed, static)

def read_config():
    path = '\Software\Synchro\Config'
    dirs = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,path) as k:
            dirs[winreg.QueryValueEx(k, "dir1")[0]] = winreg.QueryValueEx(k, "dir1_t")[0]
            dirs[winreg.QueryValueEx(k, "dir2")[0]] = winreg.QueryValueEx(k, "dir1_2")[0]
            lastrun = float(winreg.QueryValueEx(k, "lastrun")[0])
    except:
        sys.exit("Could not read config")

    return (lastrun, dirs)

def write_time(lastrun):
    path = '\Software\Synchro\Config'
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
            winreg.SetValueEx(k, "lastrun", 0, winreg.REG_SZ, lastrun)
    except:
        sys.exit("Could not write config")

if __name__ == "__main__":
    main()