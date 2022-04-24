CC=gcc -g #-Wall 
Clang=clang-6.0 -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone
PATH1=../../stub_model/source-new
PATH2=../../stub_model/header-new
PATH3=../../CA_variants

INC=-I $(PATH1) -I $(PATH2) -I $(PATH3)
#MAIN_VAR1=simple_main
#$(MAIN_VAR1):$(MAIN_VAR1).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
#	$(CC) -o $(MAIN_VAR1) $(MAIN_VAR1).c $(INC)

#MAIN_VAR2=main_bic
#$(MAIN_VAR2):$(MAIN_VAR2).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
#	$(CC) -o $(MAIN_VAR2) $(MAIN_VAR2).c $(INC)

GENERAL8=script_tcp_ack_function_v8
$(GENERAL8):$(GENERAL8).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERAL8).c $(INC)

GENERALAGG=script_tcp_ack_function_update_acks_only
$(GENERALAGG):$(GENERALAGG).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERALAGG).c $(INC)

GENERALORG1=script_tcp_ack_function_org_v1
$(GENERALORG1):$(GENERALORG1).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERALORG1).c $(INC)

GENERAL7=script_tcp_ack_function_v7
$(GENERAL7):$(GENERAL7).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERAL7).c $(INC)

GENERAL6=script_tcp_ack_function_v6
$(GENERAL6):$(GENERAL6).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERAL6).c $(INC)

GENERAL5=script_tcp_ack_function_v5
$(GENERAL5):$(GENERAL5).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERAL5).c $(INC)

GENERAL4=script_tcp_ack_function_v4
$(GENERAL4):$(GENERAL4).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERAL4).c $(INC)

GENERALORG=script_tcp_ack_function_org
$(GENERALORG):$(GENERALORG).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERALORG).c $(INC)

GENERAL3=script_tcp_ack_function_v3
$(GENERAL3):$(GENERAL3).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERAL3).c $(INC)

GENERAL2=script_tcp_ack_function_v2
$(GENERAL2):$(GENERAL2).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERAL2).c $(INC)

GENERAL1=script_tcp_ack_function_v1
$(GENERAL1):$(GENERAL1).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERAL1).c $(INC)

GENERAL=script_tcp_ack_function
$(GENERAL):$(GENERAL).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(GENERAL).c $(INC)

MAIN=aimd_simple_original
$(MAIN):$(MAIN).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(MAIN).c $(INC)

AGT=aimd_simple_aggregation
$(AGT):$(AGT).c $(wildcard $(PATH1)/*.c) $(wildcard $(PATH3)/*.c) $(wildcard $(PATH2)/*.h)
	$(Clang) $(AGT).c $(INC)
