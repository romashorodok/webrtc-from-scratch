
class Rav1e:
	def __init__(
		self,
		width: int,
		height: int,
		sample_aspect_ratio_num: int,
		sample_aspect_ratio_den: int,
		bit_depth: int,
		chroma_sampling: int,
	    time_base_num: int,
		time_base_dem: int,
	) -> None: ...

	async def receive_packet(self) -> Any: ...
