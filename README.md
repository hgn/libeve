# libev

## Compile Options

Per default SDT markers are compiled into the executable.
If you don't want these markers to be in your code, please
compile:

```
make SDT=disable
```

## Perf Markers - Usage

Assume your executable is named `test`, it is successfully linked to libev and
resits in the current directory. Installing can be done in the following way

List the available SDT markers in `test` executable:

```
perf list sdt ./test
```

To record SDT markers they must be first enabled via `perf probe`

```
perf probe -x ./test %sdt_libev:ev_add
perf probe -x ./test %sdt_libev:epoll_wait_enter
perf probe -x ./test %sdt_libev:epoll_wait_return
```

Now record the events

```
perf record -e sdt_libev:ev_add,sdt_libev:epoll_wait_enter,sdt_libev:epoll_wait_return ./test
```

## Available Systemtap Markers

- `epoll_wait`
- `trigger_read_write`
- `trigger_timeout_oneshot`
- `trigger_timeout_periodic`
- `trigger_signal`
- `ev_new`
- `ev_entry_new`
- `ev_add`
- `ev_add_read_write`
- `ev_add_timeout_oneshot`
- `ev_add_timeout_periodic`
- `ev_add_signal`
- `ev_del`
- `ev_timer_cancel`

### `epoll_wait`

Called, directly after `epoll_wait` return

Argument(s):

- int nfds

### `trigger_read_write`

Directly before user callback is called

Argument(s):

- int fd

### `trigger_timeout_oneshot`

Directly before user callback is called


### `trigger_timeout_periodic`

Directly before user callback is called


### `trigger_signal`

Directly before user callback is called

Argument(s):

- int signal number
- int pid
