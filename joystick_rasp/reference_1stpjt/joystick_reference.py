import spidev


class Joystick:
    def __init__(self, swt_ch=0, vrx_ch=1, vry_ch=2):
        self.spi = spidev.SpiDev()  # SPI 열기
        self.spi.open(0, 0)
        self.spi.max_speed_hz = 1000000  # SPI 속도 설정

        # Define sensor channels
        # (channels 3 to 7 unused)
        self.swt_channel = swt_ch  # default : B의 값을 CH0으로 설정
        self.vrx_channel = vrx_ch  # default : X의 값을 CH1로 설정
        self.vry_channel = vry_ch  # default : Y의 값을 CH2로 설정

        self.old_max = 1023
        self.old_min = 0

    def read_channel(self, channel):  # 채널의 값을 읽기
        adc = self.spi.xfer2([1, (8 + channel) << 4, 0])
        data = ((adc[1] & 3) << 8) + adc[2]
        return data

    def get_converted_swt(self):
        swt_val = self.read_channel(self.swt_channel)  # B(SW)의 값을 읽음

        if swt_val > 512:
            cnv_s_val = 1
        else:
            cnv_s_val = 0

        return int(cnv_s_val)

    def get_converted_vrx(self, new_x_min = 0, new_x_max = 99):
        vrx_pos = self.read_channel(self.vrx_channel)  # x의 값을 읽음
        cnv_x_pos = ((vrx_pos - self.old_min) * (new_x_max - new_x_min) / (self.old_max - self.old_min)) + new_x_min

        if 45 < cnv_x_pos < 55:  # deadzone
            cnv_x_pos = 50

        return int(cnv_x_pos)

    def get_converted_vry(self, new_y_min = 0, new_y_max = 99):
        vry_pos = self.read_channel(self.vry_channel)  # y의 값을 읽음
        cnv_y_pos = ((vry_pos - self.old_min) * (new_y_max - new_y_min) / (self.old_max - self.old_min)) + new_y_min

        if 45 < cnv_y_pos < 55:  # deadzone
            cnv_y_pos = 50

        return int(99 - cnv_y_pos)