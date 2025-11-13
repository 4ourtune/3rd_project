#include "ccu.h"

#define BUF_SIZE 8
#define MOTOR_STOP 50
#define CYCLE_INTERVAL_US 40000 // 40000us = 40ms

void run_ccu (void)
{
    static char user_cmd[BUF_SIZE];

    static ToFData_t tof_latest_data;
    static UltrasonicData_t ult_latest_data[ULTRASONIC_COUNT];

    static uint64 aeb_last_updated_time = 0;
    static uint64 aps_last_updated_time = 0;

    static int pre_motor_x = MOTOR_STOP;
    static int pre_motor_y = MOTOR_STOP;

    while (1)
    {
        /* Keep previous motor value */
        int motor_x = pre_motor_x;
        int motor_y = pre_motor_y;

        /* Check user commands */
        /* Command priority: 2 (High value - higher priority) */
        if (Bluetooth_RxQueue_PopString(user_cmd, BUF_SIZE))
        {
//            my_printf("%s\n", user_cmd);
            switch (user_cmd[0])
            {
                case 'M' : // 'Move'
                    Set_APS_State(0); // APS turns off when user inputs a 'Move' command

                    // Set motor inputs
                    user_cmd[5] = '\0';
                    motor_y = atoi(user_cmd + 3);
                    user_cmd[3] = '\0';
                    motor_x = atoi(user_cmd + 1);

                    break;

                case 'P' : // 'Automatic parking'
                    Set_APS_State(1); // APS on

                    break;

                default : // Invalid command
                    break;
            }
        }

        /* Get ToF data */
        ToF_ProcessQueue();
        ToF_GetLatestData(&tof_latest_data);
//        my_printf("0/%lf ", tof_latest_data.distance_m);

        /* Get ultrasonic data */
        Ultrasonic_ProcessQueue();
        for (int i = 0; i < ULTRASONIC_COUNT; i++)
        {
            Ultrasonic_GetLatestData(i, &ult_latest_data[i]);
//            my_printf("%d/%d ", ult_latest_data[i].distance_mm);
        }
//        my_printf("\n");

        /* Check AEB */
        /* Command priority: 3 */
        uint64 cur_time = getTimeUs();
        if (cur_time - aeb_last_updated_time >= CYCLE_INTERVAL_US)
        {
            AEB_UpdateState(&tof_latest_data, CYCLE_INTERVAL_US);
            aeb_last_updated_time = cur_time;
        }

        if (AEB_GetState() && !Get_APS_State())
        {
            Set_APS_State(0); // APS off
            AEBAlert_On();
            if (motor_y > MOTOR_STOP) // If it moves forward
            {
                motor_x = motor_y = MOTOR_STOP;
            }
        }
        else
        {
            AEBAlert_Off();
        }

        /* Check APS */
        /* Command priority: 1 */
        if (Get_APS_State())
        {
            int aps_result_updated = 0;

            cur_time = getTimeUs();
            if (cur_time - aps_last_updated_time >= CYCLE_INTERVAL_US)
            {
                aps_result_updated = Update_APS_Result(&tof_latest_data, ult_latest_data, CYCLE_INTERVAL_US);
                aps_last_updated_time = cur_time;
            }

            if (aps_result_updated)
            {
                int is_done;
                Get_APS_Result(&motor_x, &motor_y, &is_done);
                if (is_done)
                {
                    Set_APS_State(0); // Terminate APS when it's done or has problem
                }
            }
        }

        /* Check motor control input */
        if (!(motor_x == pre_motor_x && motor_y == pre_motor_y))
        {
//            my_printf("%d %d\n", motor_x, motor_y);
            if (MotorController_ProcessJoystickInput(motor_x, motor_y)) // Controll motor
            {
                pre_motor_x = motor_x;
                pre_motor_y = motor_y;
            }
        }
    }
}