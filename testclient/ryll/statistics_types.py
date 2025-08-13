from collections import defaultdict
import tkinter as tk

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

from ryll.common import _log


class NoStatistics:
    def __init__(self):
        ...

    def increment_statistic(self, stat_name, stat_value):
        ...

    def display_statistics(self):
        ...

    def cascade_update(self):
        ...

    def get_upper_window(self):
        return None


class TkinterStatistics:
    def __init__(self):
        self.window = tk.Tk()
        self.window.geometry('500x500')
        self.window.resizable(False, False)
        self.window.title('Statistics')
        self.statistics_figure, self.statistics_axes = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.statistics_figure, master=self.window)
        self.canvas.get_tk_widget().pack()

        self.statistics = {}
        self.previous_statistics = {}
        self.timeseries_statistics = defaultdict(list)

    def _log(self, msg, severity=''):
        _log(self.thread_name, msg, severity=severity)

    def increment_statistic(self, stat_name, stat_value):
        if stat_name not in self.statistics:
            self.statistics[stat_name] = stat_value
            return

        self.statistics[stat_name] += stat_value

    def display_statistics(self):
        self.statistics_axes.cla()

        for name in self.statistics:
            delta = self.statistics[name] - self.previous_statistics.get(name, 0)
            self.previous_statistics[name] = self.statistics[name]

            self.timeseries_statistics[name].append(delta)
            self.timeseries_statistics[name] = self.timeseries_statistics[name][-18:]
            _log('statistics', f'{name}: {self.timeseries_statistics[name]}')
            self.statistics_axes.plot(
                self.timeseries_statistics[name],
                label=name)

        self.statistics_axes.legend(
            loc='upper center', shadow=True, fontsize='small')

        self.canvas.draw()

    def get_upper_window(self):
        return self.window

    def cascade_update(self):
        self.window.update()


CHOICES = {
    'none': NoStatistics,
    'tkinter': TkinterStatistics
}
