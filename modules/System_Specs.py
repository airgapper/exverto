import datetime

import cpuinfo
import gpustat
import psutil



class System_Specs:
    def cpu():
        global cpu_info_data
        cpu_info_data = cpuinfo.get_cpu_info()
        return {'info': cpu_info_data,
                'count': psutil.cpu_count(),
                'usage': psutil.cpu_percent(),
                'percent': psutil.cpu_percent(percpu=True),
                'stats': dict(psutil.cpu_stats()._asdict()),
                'freq': dict(psutil.cpu_freq()._asdict()),
                'times': dict(psutil.cpu_times()._asdict()),
                'times_percent': dict(psutil.cpu_times_percent()._asdict()),
                'mem': dict(psutil.virtual_memory()._asdict()),
                'swap': dict(psutil.swap_memory()._asdict()),
                'boot_time' : datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
                }

    def gpu():
        global gpu_info_data, gpu_info_expires
        cpu_info_data = None
        gpu_info_data = None
        try:

            if gpu_info_data is None:
                query_result = gpustat.new_query()
                gpu_info_data = [dict(gpu) for gpu in query_result]
        except:
            gpu_info_data = []
        return gpu_info_data
