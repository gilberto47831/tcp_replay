/*
Gilberto Ramirez - vwz745
File: cpu_sched.c
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct PCB_st {
    int ProcId;
    int ProcPR;
    int CPUburst;
    int myReg[8];
    int queueEnterClock;
    int waitingTime;
    struct PCB_st *next;
} PCB_st;
    
typedef struct List {
    PCB_st *Head;
    PCB_st *Tail;
} List;

//function prototypes
PCB_st *PCBMaxPR(List *PCBList);
PCB_st *PCBMin(List *PCBList);
void Enlist(List *PCBList, PCB_st *PCB);
PCB_st *newPCB(int ProcId, int ProcPr, int CPUburst);
List *newLinkedList(void);
int processSwitches(int argc, char *argv[], char **filename, char **alg, int *quantum);
void FIFO_Scheduling(List *PCBList, int *CPUReg, int *CLOCK, int *Total_waiting_time
                     ,int *Total_turnaround_time, int *Total_job);
void SJF_Scheduling(List *PCBList, int *CPUReg, int *CLOCK, int *Total_waiting_time
                     ,int *Total_turnaround_time, int *Total_job);
void PR_Scheduling(List *PCBList, int *CPUReg, int *CLOCK, int *Total_waiting_time
                     ,int *Total_turnaround_time, int *Total_job);
void RR_Scheduling(List *PCBList, int *CPUReg, int *CLOCK, int *Total_waiting_time
                     ,int *Total_turnaround_time, int *Total_job, int quantum);

int main(int argc, char *argv[]) {
    
    int CPUreg[8]; //Defining registers along with varibles for timing statistics
    int CLOCK = 0;
    int Total_waiting_time = 0;
    int Total_turnaround_time = 0;
    int Total_job = 0;

    List *PCBList = newLinkedList(); //new list of PCB's
    FILE *fp;
    char *filename;
    char *alg;
    int quantum;
    
    //verify commandline args and store them into variables
    if(processSwitches(argc, argv, &filename, &alg, &quantum) == -1) {
        fprintf(stderr,"Usage: prog -alg [FIFO|SJF|PR|RR] [-quantum integer(ms)] -input"
                       "[input_file_name.txt]\n");
        exit(1);
    }

    //io
    if((fp = fopen(filename, "r")) == NULL) {
        fprintf(stderr,"Unable to open file\n");
        exit(1);
    }

    int ProcId;
    int ProcPR;
    int CPUburst;
    //get data from input file
    while(fscanf(fp, "%d %d %d", &ProcId, &ProcPR, &CPUburst) == 3) {
        //create new PCB and add to end of list
        PCB_st *PCB = newPCB(ProcId, ProcPR, CPUburst);
        Enlist(PCBList, PCB);
    }
    fclose(fp);

    //print header info
    printf("Student Name: Gilberto Ramirez\n");
    printf("Input File Name: %s\n", filename);
    printf("CPU Scheduling Alg: %s\n", alg);

    //perform the specificed alg scheduling 
    if(strcmp(alg, "FIFO") == 0)
        FIFO_Scheduling(PCBList, CPUreg, &CLOCK, &Total_waiting_time, &Total_turnaround_time, &Total_job);

    else if(strcmp(alg, "SJF") == 0)
        SJF_Scheduling(PCBList, CPUreg, &CLOCK, &Total_waiting_time, &Total_turnaround_time, &Total_job);

    else if(strcmp(alg, "PR") == 0)
        PR_Scheduling(PCBList, CPUreg, &CLOCK, &Total_waiting_time, &Total_turnaround_time, &Total_job);

    else if(strcmp(alg, "RR") == 0)
        RR_Scheduling(PCBList, CPUreg, &CLOCK, &Total_waiting_time, &Total_turnaround_time, &Total_job
                     , quantum);
    else {
        fprintf(stderr, "Not a valid scheduling algorithm!\n");
        exit(1);
    }

    free(PCBList);
    return 0;
}
/*
 * Function processSwitches
 * Usage: int status = processSwitches(argc,argv,&filename,&alg,&quantum)
 * Returns -1 on malformed argument switches, 0 on success
 * ----------------------------------------------------
 * Processes command line arguments verifying correctness and stores
 * filename and algorithm to be used in their respective variables. If RR is
 * specified, then quantum is obtained as well
 */

int processSwitches(int argc, char *argv[], char **filename, char **alg, int *quantum) {

    int i;
    //The min argument count expected
    if(argc < 5)
        return -1;
    
    //iterate through arguments
    for(i = 1;i < argc;i++) {
        //-alg case
        if(strcmp(argv[i], "-alg") == 0) {
            //store the next arg into alg
            i+=1;
            *alg = argv[i];
            
            //if RR, then store the the argument 2 places ahead into quantum
            if(strcmp(argv[i], "RR") == 0) {
                i+=2;
                if(i >= argc)
                    return -1;

                //convert to integer
                *quantum = atoi(argv[i]);
            }
            //if at any point i is bigger than or equal to argc, then bad usage
            if(i >= argc)
                return -1;
        }
        //input case, store the following arg after into filename
        else if(strcmp(argv[i], "-input") == 0) {
            i+=1;
            *filename = argv[i];
        }
        else
            return -1;
    }
    return 0;
}
/*
 * Function: newLinkedList
 * Usage: List *PCBList = newLinkedList();
 * --------------------------------------
 * Creates a dynamically allocated list and returns a pointer to it.
 */

List *newLinkedList(void) {
    List *list;
    list = (List *) malloc(sizeof(List)); //dynamically allocate
    //error case
    if(!list) {
        fprintf(stderr,"Memory allocation error!");
        return NULL;
    }
    //init to null
    list->Head = NULL;
    list->Tail = NULL;
    return list;
}
/*
 * Function: newPCB
 * Usage: PCB_st *PCB = newPCB(ProcId, ProcPR, CPUburst);
 * ---------------------------------------------------
 * Creates a new dynamically allocated PCB structure
 * and inits it with parameter values. Returns a pointer to it.
 *
 */
PCB_st *newPCB(int ProcId, int ProcPR, int CPUburst) {
    PCB_st *PCB;
    PCB = (PCB_st *) malloc(sizeof(PCB_st)); //dynamic allocate
    //err chcking
    if(!PCB) {
        fprintf(stderr,"Memory allocation error!");
        return NULL;
    }
    //init strcutre elements
    PCB->ProcId = ProcId;
    PCB->ProcPR = ProcPR;
    PCB->CPUburst = CPUburst;
    PCB->queueEnterClock = 0;
    PCB->waitingTime = 0;
    PCB->next = NULL;
    memset(PCB->myReg, ProcId, 8);
    return PCB;
}
/*
 * Function: Enlist
 * Usage: Enlist(PCBList, PCB);
 * ------------------------------
 * Adds a new PCB structure to the end of the PCBList.
 *
 */
void Enlist(List *PCBList, PCB_st *PCB) {
    //empty list case
    if(!PCBList->Head) {
        PCBList->Head = PCB;
        PCBList->Tail = PCB;
        return;
    }
    //else add to end of list and assign it as new tail
    PCBList->Tail->next = PCB;
    PCBList->Tail = PCB;
}
/*
 * Function: Delist
 * Usage: PCB_st *PCB = Delist(PCBList);
 * -----------------------------------
 * Remove the PCB structure at the head of the list
 * and returns it.
 *
 */
PCB_st *Delist(List *PCBList) {
    //emtpy list case
    if(!PCBList->Head) {
        return NULL;
    }
    //else new head is the next element in the list and return head
    PCB_st *PCB = PCBList->Head;
    PCBList->Head = PCB->next;
    return PCB;
}/*
 * Function: PCBMin
 * Usage: PCB_st *PCB = PCBMin(PCBList);
 * --------------------------------------
 * Finds the PCB with the min cpu burst time
 * and break it off of the list and returns it. Used
 * in SJF_Scheduling.
 *
 */
PCB_st *PCBMin(List *PCBList) {

    //emtpy case
    if(!PCBList->Head)
        return NULL;

    PCB_st *PCB, *min, *prev;
    PCB = min = PCBList->Head;

    //iterate through list finding min cpuburst
    while(PCB) {
        if(PCB->CPUburst < min->CPUburst)
            min = PCB;
        PCB = PCB->next;
    }

    //head case
    if(min == PCBList->Head)
        return Delist(PCBList);

    //middle case
    PCB = PCBList->Head;

    while(PCB) {
        prev = PCB;
        PCB = PCB->next;
        if(PCB == min)
            break;
    }
    prev->next = PCB->next;
    //if pcb was tail, then new tail is prev
    if(PCB == PCBList->Tail)
        PCBList->Tail = prev;

    return min;
}
/*
 * Function: PCBMaxPR
 * Usage: PCB_st *PCB = PCBMaxPR(PCBList);
 * --------------------------------------
 * Finds the PCB with the highest Priority
 * and break it off of the list and returns it. Used
 * in PR_Scheduling.
 *
 */
PCB_st *PCBMaxPR(List *PCBList) {

    //empty list
    if(!PCBList->Head)
        return NULL;

    PCB_st *PCB, *max, *prev;
    PCB = max = PCBList->Head;

    //iterate through list finidng max PR
    while(PCB) {
        if(PCB->ProcPR > max->ProcPR)
            max = PCB;
        PCB = PCB->next;
    }

    //head case
    if(max == PCBList->Head)
        return Delist(PCBList);

    //middle case
    PCB = PCBList->Head;

    while(PCB) {
        prev = PCB;
        PCB = PCB->next;
        if(PCB == max)
            break;
    }
    //break it off
    prev->next = PCB->next;
    //if PCB was tail, assign prev as new Tail
    if(PCB == PCBList->Tail)
        PCBList->Tail = prev;

    return max;
}
/*
 * Function: FIFO_Scheduling
 * Usage: FIFO_Scheduling(PCBList, CPUReg, &CLOCK, &Total_waiting_time,&Total_turnaround_time
 *                       ,&Total_job);
 * -----------------------------------------------------------------------------
 * Performs the FIFO algorithm in the case that alg = FIFO. Frees all PCB once they
 * are completed. Once PCB list is NULL, prints all job statistics.
 * 
 */
void FIFO_Scheduling(List *PCBList, int *CPUReg, int *CLOCK, int *Total_waiting_time
                    ,int *Total_turnaround_time, int *Total_job) {
    int i; 
    PCB_st *PCB = PCBList->Head;
    PCB_st *tmp;
    //iterate through list
    while(PCB) {
       //context switching
       for(i = 0;i < 8;i++) {
           CPUReg[i] = PCB->myReg[i];
       }
       //work being done on CPU
       for(i = 0;i < 8;i++) {
           CPUReg[i]+=1;
       }
       //context switching
       for(i = 0;i < 8;i++) {
           PCB->myReg[i] = CPUReg[i];
       }
       //data collection for performance metrics
       PCB->waitingTime = PCB->waitingTime + *CLOCK - PCB->queueEnterClock;
       *Total_waiting_time = *Total_waiting_time + PCB->waitingTime;
       *CLOCK = *CLOCK + PCB->CPUburst;
       *Total_turnaround_time = *Total_turnaround_time + *CLOCK;
       *Total_job = *Total_job + 1;

       //printing info and freeing pcb
       printf("Process %d is completed at %d ms\n", PCB->ProcId, *CLOCK);
       tmp = PCB;
       PCB = PCB->next;
       free(tmp);
    }
    //printing performance metrics
    printf("Average Waiting time = %.2lf ms     (%d/%d)\n", ((double)*Total_waiting_time / *Total_job)
                                                         , *Total_waiting_time, *Total_job );
    printf("Average Turnaround time = %.2lf ms (%d/%d)\n", ((double)*Total_turnaround_time / *Total_job)
                                                         , *Total_turnaround_time, *Total_job);
    printf("Throughput = %.2lf jobs per ms      (%d/%d)\n",((double)*Total_job / *CLOCK), *Total_job, *CLOCK);

}
/*
 * Function: SJF_Scheduling
 * Usage: SJF_Scheduling(PCBList, CPUReg, &CLOCK, &Total_waiting_time,&Total_turnaround_time
 *                       ,&Total_job);
 * -----------------------------------------------------------------------------
 * Performs the SJF algorithm in the case that alg = SJF. Calls the PCBMin() function
 * and obtains the PCB with least CPUburst as the next process to get CPU time.
 * Frees all PCB once they are completed.Once PCB list is NULL, prints all job statistics.
 * 
 */
void SJF_Scheduling(List *PCBList, int *CPUReg, int *CLOCK, int *Total_waiting_time
                    ,int *Total_turnaround_time, int *Total_job) {
    int i; 
    //get the PCB with min cpu burst time
    PCB_st *PCB = PCBMin(PCBList);
    PCB_st *tmp;
    //iterate liste
    while(PCB) {
        //context switch
       for(i = 0;i < 8;i++) {
           CPUReg[i] = PCB->myReg[i];
       }
       //cpu work
       for(i = 0;i < 8;i++) {
           CPUReg[i]+=1;
       }
       //context switch
       for(i = 0;i < 8;i++) {
           PCB->myReg[i] = CPUReg[i];
       }
       //statistic gathering
       PCB->waitingTime = PCB->waitingTime + *CLOCK - PCB->queueEnterClock;
       *Total_waiting_time = *Total_waiting_time + PCB->waitingTime;
       *CLOCK = *CLOCK + PCB->CPUburst;
       *Total_turnaround_time = *Total_turnaround_time + *CLOCK;
       *Total_job = *Total_job + 1;

       //print job end time and free Pcb
       printf("Process %d is completed at %d ms\n", PCB->ProcId, *CLOCK);
       tmp = PCB;
       //get the next pcb with min cpu burst
       PCB = PCBMin(PCBList);
       free(tmp);
    }
    //print performance metrics
    printf("Average Waiting time = %.2lf ms     (%d/%d)\n", ((double)*Total_waiting_time / *Total_job)
                                                         , *Total_waiting_time, *Total_job );
    printf("Average Turnaround time = %.2lf ms (%d/%d)\n", ((double)*Total_turnaround_time / *Total_job)
                                                         , *Total_turnaround_time, *Total_job);
    printf("Throughput = %.2lf jobs per ms      (%d/%d)\n",((double)*Total_job / *CLOCK), *Total_job, *CLOCK);

}
/*
 * Function: PR_Scheduling
 * Usage: PR_Scheduling(PCBList, CPUReg, &CLOCK, &Total_waiting_time,&Total_turnaround_time
 *                       ,&Total_job);
 * -----------------------------------------------------------------------------
 * Performs the PR algorithm in the case that alg = PR. Each iteratation obtains
 * the PCB job with the highest PR value. Frees all PCB once they
 * are completed. Once PCB list is NULL, prints all job statistics.
 * 
 */
void PR_Scheduling(List *PCBList, int *CPUReg, int *CLOCK, int *Total_waiting_time
                    ,int *Total_turnaround_time, int *Total_job) {
    int i; 
    //get highest priority job
    PCB_st *PCB = PCBMaxPR(PCBList);
    PCB_st *tmp;
    //iterate through liset
    while(PCB) {
        //context switch
       for(i = 0;i < 8;i++) {
           CPUReg[i] = PCB->myReg[i];
       }
       //cpu work
       for(i = 0;i < 8;i++) {
           CPUReg[i]+=1;
       }
       //context switch
       for(i = 0;i < 8;i++) {
           PCB->myReg[i] = CPUReg[i];
       }
       //data collection
       PCB->waitingTime = PCB->waitingTime + *CLOCK - PCB->queueEnterClock;
       *Total_waiting_time = *Total_waiting_time + PCB->waitingTime;
       *CLOCK = *CLOCK + PCB->CPUburst;
       *Total_turnaround_time = *Total_turnaround_time + *CLOCK;
       *Total_job = *Total_job + 1;

       //print job end time and get the next highest PR PCB
       printf("Process %d is completed at %d ms\n", PCB->ProcId, *CLOCK);
       tmp = PCB;
       PCB = PCBMaxPR(PCBList);
       free(tmp);
    }
    //print performance metrics
    printf("Average Waiting time = %.2lf ms     (%d/%d)\n", ((double)*Total_waiting_time / *Total_job)
                                                         , *Total_waiting_time, *Total_job );
    printf("Average Turnaround time = %.2lf ms (%d/%d)\n", ((double)*Total_turnaround_time / *Total_job)
                                                         , *Total_turnaround_time, *Total_job);
    printf("Throughput = %.2lf jobs per ms      (%d/%d)\n",((double)*Total_job / *CLOCK), *Total_job, *CLOCK);

}
/*
 * Function: RR_Scheduling
 * Usage: RR_Scheduling(PCBList, CPUReg, &CLOCK, &Total_waiting_time,&Total_turnaround_time
 *                       ,&Total_job, &quantum);
 * -----------------------------------------------------------------------------
 * Performs the RR algorithm in the case that alg = RR. Gets the next job in the 
 * order in which it came and give it quantum time of CPU time. If job cpu burst is less
 * than quantum, then clock subtracted by the cpuburst and frees it. Else it subs it
 * cpuburst by quantum time and adds it back to list
 * 
 */
void RR_Scheduling(List *PCBList, int *CPUReg, int *CLOCK, int *Total_waiting_time
                    ,int *Total_turnaround_time, int *Total_job, int quantum) {
    int i; 
    //get the next job
    PCB_st *PCB = Delist(PCBList);
    PCB_st *tmp;
    //iterate through list
    while(PCB) {
       //set next to null as to not create infinte loop if we have to reinsert into list
       PCB->next = NULL;
       //context switch
       for(i = 0;i < 8;i++) {
           CPUReg[i] = PCB->myReg[i];
       }
       //cpu work
       for(i = 0;i < 8;i++) {
           CPUReg[i]+=1;
       }
       //context switch
       for(i = 0;i < 8;i++) {
           PCB->myReg[i] = CPUReg[i];
       }
       //if cpu burst is less or equal to quantum
       if(PCB->CPUburst <= quantum) {
           //data collection
           PCB->waitingTime = PCB->waitingTime + *CLOCK - PCB->queueEnterClock;
           *Total_waiting_time = *Total_waiting_time + PCB->waitingTime;
           *CLOCK = *CLOCK + PCB->CPUburst;
           *Total_turnaround_time = *Total_turnaround_time + *CLOCK;
           *Total_job = *Total_job + 1;

           //job end time
           printf("Process %d is completed at %d ms\n", PCB->ProcId, *CLOCK);
           tmp = PCB;
           //get next job
           PCB = Delist(PCBList);
           free(tmp);
       }
       //if job is not finished
       else {
           PCB->waitingTime = PCB->waitingTime + *CLOCK - PCB->queueEnterClock;
           *CLOCK = *CLOCK + quantum;
           PCB->CPUburst = PCB->CPUburst - quantum;
           PCB->queueEnterClock = *CLOCK;
           //insert back into list
           Enlist(PCBList, PCB);
           //get next job
           PCB = Delist(PCBList);
       }
    }
    //print performance metrics
    printf("Average Waiting time = %.2lf ms     (%d/%d)\n", ((double)*Total_waiting_time / *Total_job)
                                                         , *Total_waiting_time, *Total_job );
    printf("Average Turnaround time = %.2lf ms (%d/%d)\n", ((double)*Total_turnaround_time / *Total_job)
                                                         , *Total_turnaround_time, *Total_job);
    printf("Throughput = %.2lf jobs per ms      (%d/%d)\n",((double)*Total_job / *CLOCK), *Total_job, *CLOCK);
}
