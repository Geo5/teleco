from argparse import ArgumentParser
from pathlib import Path

import pandas
import numpy as np
import matplotlib.pyplot as plt


def read_df(trace_file: Path) -> pandas.DataFrame:
    column_names = [
        "event_type",
        "time",
        "from_node",
        "to_node",
        "packet_type",
        "packet_size",
        "flags",
        "flow_id",
        "packet_src",
        "packet_dst",
        "seq",
        "packet_id",
    ]
    return pandas.read_csv(trace_file, sep=" ", names=column_names)


def rate(
    data_frame: pandas.DataFrame,
    event_type_requested: str,
    to_node_requested: int,
    packet_type_requested: str,
    granularity: float,
):
    """
    This function reads tracefiles of ns2 and counts the datarate of certain packet stream identified by its packet type, destination node and event type.

    Parameters
    ----------
    trace_file : path of the file we want to analyze.
    event_type_requested : event type
    to_node_requested : destination node
    packet_type_requested : packet type
    granularity : is the time window (in seconds) over which averages are taken

    Returns
    -------
    time_axis : time axis
    computed_rate : computed rate
    """

    selection_criteria = (
        (data_frame["event_type"] == event_type_requested)
        & (data_frame["to_node"] == to_node_requested)
        & (data_frame["packet_type"] == packet_type_requested)
    )
    selected_events = data_frame[selection_criteria]
    time_axis = np.arange(start=0, stop=data_frame["time"].max(), step=granularity)
    computed_rate = []

    for t in time_axis:
        bits_in_interval = 0.0
        my_data = selected_events[
            (selected_events["time"] >= t)
            & (selected_events["time"] < (t + granularity))
        ]
        my_iter = my_data.iterrows()
        for idx, row in my_iter:
            bits_in_interval = bits_in_interval + 8.0 * row["packet_size"]

        computed_rate.append(bits_in_interval / (granularity))

    # time_axis=np.array(time_axis)
    computed_rate = np.array(computed_rate)  # convert from list to array
    return (time_axis, computed_rate)


parser = ArgumentParser()
parser.add_argument(
    "tr",
    nargs="*",
    type=Path,
    help="Input .tr file",
    default=sorted(Path(__file__).parent.glob("*.tr")),
)
parser.add_argument("-g", "--granularity", type=float, help="Granularity", default=0.3)
args = parser.parse_args()

MAX_TIME = 50.0
MAX_LOSS = 100.0
font_size = plt.rcParams["font.size"]
text_bbox_padding = 0.1

fig, axs = plt.subplots(
    2, len(args.tr), sharex="all", sharey="row", squeeze=False, layout="tight"
)
axs[0, 0].set_ylabel("Throughput")
axs[1, 0].set_ylabel("Loss rate in %")
axs[1, 0].set_ylim(-5.0, MAX_LOSS)
granularity = args.granularity

for col_idx, tr in enumerate(args.tr):
    axs[0, col_idx].set_title(tr.name)
    axs[1, col_idx].set_xlabel("Time in s")
    axs[1, col_idx].set_xlim(0.0, MAX_TIME)
    annotate_poses = {0: [], 1: []}
    data_frame = read_df(tr)
    print(tr.name)
    for pt, sink_node, label, color in [
        ("cbr", 5, "cbr", "tab:orange"),
        ("tcp", 6, "ftp", "tab:blue"),
    ]:
        mean_pkt_size = data_frame[
            (data_frame["event_type"] == "r")
            & (data_frame["to_node"] == 2)
            & (data_frame["packet_type"] == pt)
        ]["packet_size"].mean()
        print(f"\tMean packet size for {label}: {mean_pkt_size}")
        time, recv = rate(
            data_frame,
            "r",
            to_node_requested=sink_node,
            packet_type_requested=pt,
            granularity=granularity,
        )
        axs[0, col_idx].plot(time, recv, label=label, color=color)
        # Loss rate
        _, send = rate(
            data_frame,
            "r",
            to_node_requested=2,
            packet_type_requested=pt,
            granularity=granularity,
        )
        loss = np.zeros_like(recv)
        send_mask = send > 0.0
        loss[send_mask] = (send[send_mask] - recv[send_mask]) / send[send_mask]
        loss_avg = (send.sum() - recv.sum()) / send.sum() * 100
        axs[1, col_idx].plot(time, loss * 100, label=label, color=color)
        # Averages
        recv_avg = recv.mean()
        axs[0, col_idx].plot(
            time,
            [recv.mean()] * len(time),
            label=label + " avg",
            linestyle="--",
            color=color,
        )
        # Calculate non-overlapping y pos for annotation
        y_pos = recv_avg
        y_offset = (text_bbox_padding + 0.1) * font_size
        for val in annotate_poses[0]:
            # Check if positions are overlapping, and offset upwards
            if y_pos <= val + 0.06 * MAX_LOSS and val <= y_pos + 0.06 * MAX_LOSS:
                y_pos = val + 0.06 * MAX_LOSS
        axs[0, col_idx].annotate(
            f"{label} avg={recv_avg/1e6:.2f}e6",
            xy=(MAX_TIME, y_pos),
            xycoords="data",
            xytext=(-text_bbox_padding * font_size, y_offset),
            textcoords="offset points",
            horizontalalignment="right",
            verticalalignment="bottom",
            family="monospace",
            bbox=dict(
                boxstyle=f"square,pad={text_bbox_padding}",
                facecolor=color,
                edgecolor="none",
            ),
        )
        annotate_poses[0].append(y_pos)
        axs[1, col_idx].plot(
            time,
            [loss_avg] * len(time),
            label=label + " avg",
            linestyle="--",
            color=color,
        )
        # Calculate non-overlapping y pos for annotation
        y_pos = max(loss_avg, 0.5)
        y_offset = (text_bbox_padding + 0.1) * font_size
        for val in annotate_poses[1]:
            # Check if positions are overlapping, and offset upwards
            if y_pos <= val + 0.06 * MAX_LOSS and val <= y_pos + 0.06 * MAX_LOSS:
                y_pos = val + 0.06 * MAX_LOSS
        axs[1, col_idx].annotate(
            f"{label} avg={loss_avg:.1f}%",
            xy=(MAX_TIME, y_pos),
            xytext=(-text_bbox_padding * font_size, y_offset),
            textcoords="offset points",
            xycoords="data",
            horizontalalignment="right",
            verticalalignment="bottom",
            family="monospace",
            bbox=dict(
                boxstyle=f"square,pad={text_bbox_padding}",
                facecolor=color,
                edgecolor="none",
            ),
        )
        annotate_poses[1].append(y_pos)
fig.suptitle(f"Granularity={granularity:.2f}s")
# The legend should be equal for all subplots, so we pick only the first to avoid duplication
lines, labels = axs[0, 0].get_legend_handles_labels()
fig.legend(lines, labels, loc="lower center", ncols=len(labels))
plt.show()
