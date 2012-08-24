# Use case: A user has a file on one srm resource (e.g Nebraska and he
# wants that this file to be replicated on all other srm resources
# that are currently "up" and have enough space.

# we need an irods rule that could be ran by user and will do the
#  following:

# a. user provides the following input:
# path (e.g. /osg/home/yaling/hello1.txt, which is collection_name plus file name, do I need to parse out the file name?
# resource group (osgSrmGroup)

# b. the rule checks that file exists on at least on srm resource. If
#not: exists with an error message

# c. if a file exists on more than one resource, verifies that file
# sizes are the same (We don't save checksum for now), if sizes are
# not the same rule exists with an error message

# d. for all resources that are "up" and have enough space (remaining
#  quota is > file size) and dont' have a copy of this file: copy the
#  file

# e. delete the file from disk cache

# Author: Yaling Zheng
# Date: May 22th, 2012

SafeReplicateRule2{
	if (*debug == "on"){
	  writeLine("stdout", "the parameters values are: ResourceGroup= *ResourceGroup");}
	# Find where the cache resource is (cache resource is the resource whose type is unix file system)
	*ContInxOld = 1;
	*condition_q="RESC_GROUP_NAME = '*ResourceGroup' and RESC_TYPE_NAME  = 'unix file system'"
	msiMakeQuery("RESC_NAME", *condition_q, *Query);
	msiExecStrCondQuery(*Query, *QueryOut);
	msiGetContInxFromGenQueryOut(*QueryOut, *ContInxNew);
	*cache = "";
 	while(*ContInxOld > 0) {
		foreach (*QueryOut){
			msiGetValByKey(*QueryOut, "RESC_NAME", *cache);
		}
                *ContInxOld = *ContInxNew;
                if(*ContInxOld > 0) {msiGetMoreRows(*Query,*QueryOut,*ContInxNew)};
        }
	if (*debug == "on"){
	   writeLine("stdout","Cache disk for *ResourceGroup is *cache");}

	# initialize *Path
	*PathItems = split(*Path, "\/");
	# e.g. osg
	*Item1 = str(elem(*PathItems, 0));
	# e.g. home
	*Item2 = str(elem(*PathItems, 1));
	# e.g. yaling
	*UserName = str(elem(*PathItems, 2));
	*FileName = str(elem(*PathItems, 3));							
	*CollectionName = "/"++"*Item1"++"/"++"*Item2"++"/"++"*UserName";
	# retrieve the user group name (as long as the user group name is not equal to the user name)
	*condition_q0 = "USER_NAME = '*UserName' and USER_GROUP_NAME not like '*UserName' and COLL_NAME = '*CollectionName'";
	msiMakeQuery("USER_NAME, USER_GROUP_NAME", *condition_q0, *Query0);
	msiExecStrCondQuery(*Query0, *QueryOut0);
	msiGetContInxFromGenQueryOut(*QueryOut0, *ContInx_q0);
	# writeLine("stdout", "ContInx_q0 = *ContInx_q0");
	*usergroup = "";
	foreach (*QueryOut0){
		msiGetValByKey(*QueryOut0, "USER_GROUP_NAME", *usergroup);
	}
	if (*debug == "on"){
	  writeLine("stdout", "usergroup = *usergroup");}
	# looking for resources that file exist in
	*condition_q1 = "USER_NAME = '*UserName' and DATA_NAME = '*FileName' and COLL_NAME = '*CollectionName' and RESC_GROUP_NAME = '*ResourceGroup'";
	msiMakeQuery("RESC_NAME, DATA_SIZE, DATA_REPL_NUM", *condition_q1, *Query1);
	if (*debug == "on"){
	    writeLine("stdout", "select RESC_NAME, DATA_SIZE, DATA_REPL_NUM where USER_NAME = '*UserName' and DATA_NAME = '*FileName' and COLL_NAME = '*CollectionName' and RESC_GROUP_NAME = '*ResourceGroup'");}
	msiExecStrCondQuery(*Query1, *QueryOut1);
	msiGetContInxFromGenQueryOut(*QueryOut1, *ContInx_q1);
	# writeLine("stdout", "ContInx_q1 = *ContInx_q1");
	*file_size = -1;
	*numberResourcesContainFile = 0;
	*fileConsistency = true;
	*resourcecontainsthefile = "";
	foreach (*QueryOut1){
	 	msiGetValByKey(*QueryOut1, "RESC_NAME", *resourcecontainsthefile);
	 	if (*debug == "on"){
		   writeLine("stdout", "*resourcecontainsthefile contains *FileName");}
	 	msiGetValByKey(*QueryOut1, "DATA_SIZE", *new_file_size);
	 	if (*file_size < 0){
	 	   *file_size = int(*new_file_size);
	 	}
	 	else{ # compare *file_size with *new_file_size
	 	      if (int(*new_file_size) != *file_size){
	 	      	 *fileConsistency = false;
	 	      		    }
	 	      }
	 	*numberResourcesContainFile = *numberResourcesContainFile + 1;
	}
	 *exit_flag = false;
	 # if no resource contain this file, we exit
	 if (*numberResourcesContainFile == 0){
	    writeLine("stdout", "No resource of the resource group *ResourceGroup contain this file *FileName");
	    *exit_flag = true;  
	 }
	 if (*fileConsistency == false){
	    writeLine("stdout", "File sizes on different resources are not consistent ... ");
	    *exit_flag = true;
	 }
	 *Copied_2_diskCache_already = false;
	if (*exit_flag == false) {
	    *Qs = 0 - int(*file_size);
	    *condition_q2 = "RESC_STATUS = 'up' and RESC_TYPE_NAME = 'MSS universal driver' and RESC_GROUP_NAME = '*ResourceGroup'";
	    msiMakeQuery("RESC_NAME", *condition_q2, *Query2);
	    msiExecStrCondQuery(*Query2, *QueryOut2);
	    msiGetContInxFromGenQueryOut(*QueryOut2, *ContInx_q2);
	    # writeLine("stdout", "ContInx_q2 = *ContInx_q2");
	    foreach (*QueryOut2){
	 	msiGetValByKey(*QueryOut2, "RESC_NAME", *currentresourcename);
		if (*debug == "on"){
	 	   writeLine("stdout", "*currentresourcename is up");}
	 	# now, we want to check whether this resource is within quota and quota user name is the User Group
	 	*condition_q3 = "QUOTA_RESC_NAME = '*currentresourcename' and QUOTA_OVER <= '*Qs' and QUOTA_USER_NAME = '*usergroup'";
	 	msiMakeQuery("QUOTA_RESC_NAME", *condition_q3, *Query3);
	 	msiExecStrCondQuery(*Query3, *QueryOut3);
	 	msiGetContInxFromGenQueryOut(*QueryOut3, *ContInx_q3);
	 	# writeLine("stdout", "ContInx_q3 = *ContInx_q3");
	 	foreach (*QueryOut3){
	 		msiGetValByKey(*QueryOut3, "QUOTA_RESC_NAME", *resourcename);
	 		if (*debug == "on"){
			   writeLine("stdout", "*resourcename has enough quota ...");}
			# The following, check whether current resource contains the file
	 		*condition_q4 = "DATA_NAME = '*FileName' and COLL_NAME = '*CollectionName' and RESC_NAME = '*resourcename'";
			msiMakeQuery("RESC_NAME", *condition_q4, *Query4);
	 		msiExecStrCondQuery(*Query4, *QueryOut4);
	 		msiGetContInxFromGenQueryOut(*QueryOut4, *ContInx_q4);
	 		# writeLine("stdout", "ContInx_q4 = *ContInx_q4");
	 		*ResourceContainFileFlag = false;
	 		foreach (*QueryOut4){
	 			if (*debug == "on"){	
				   writeLine("stdout", "resource *resourcename contains *FileName");	}
	 			*ResourceContainFileFlag = true;
	 		}
			# writeLine("stdout", "ResourceContainFileFlag = *ResourceContainFileFlag");
			# if current resource does not contain the file, we try to copy from original resource
	 		if (*ResourceContainFileFlag == false){
			   if (*debug == "on"){
			   writeLine("stdout", "Copied_2_diskCache_already=*Copied_2_diskCache_already");}
			   if (*debug == "on"){
			      writeLine("stdout", "resource *resourcename does not contain *FileName ... preparing to copy the file into this resource ...");}
	 		   # Now, copy this resource
			   *returnresult = 0;
			   if (*Copied_2_diskCache_already == false){
			        if (*debug == "on"){
				  writeLine("stdout", "Copy file to *resourcename");}
				
				# *condition_q5 = "USER_NAME = '*UserName' and DATA_NAME = '*FileName' and RESC_NAME = '*resourcecontainsthefile'";
				*condition_q5 = "COLL_NAME = '*CollectionName' and DATA_NAME = '*FileName' and RESC_NAME = '*resourcecontainsthefile'";
      				msiMakeQuery("RESC_NAME, DATA_NAME, DATA_REPL_NUM", *condition_q5, *Query5);
      				msiExecStrCondQuery(*Query5, *QueryOut5);
      				msiGetContInxFromGenQueryOut(*QueryOut5, *ContInx_q5);
				# writeLine("stdout", "ContInx_q5 = *ContInx_q5");
				*replica = 0;
                                foreach (*QueryOut5){
					msiGetValByKey(*QueryOut5, "DATA_REPL_NUM", *replica);
				      # writeLine("stdout", "replNum = *replica")				
				      }
				if (*debug == "on"){
       				   writeLine("stdout", "source replNum = *replica");}
			   	*returnresult = msiDataObjRepl(*Path, "destRescName=*resourcename++++rescName=*resourcecontainsthefile++++replNum=*replica", *Status);
				if (errorcode(*returnresult) >= 0) {
				   writeLine("stdout", "The file *FileName has been successfully copied from resource *resourcecontainsthefile to resource *resourcename");
				   *Copied_2_diskCache_already = true;
				   *condition_q6="RESC_GROUP_NAME = '*ResourceGroup' and RESC_TYPE_NAME  = 'unix file system'"
				   msiMakeQuery("RESC_NAME", *condition_q6, *Query6);
				   msiExecStrCondQuery(*Query6, *QueryOut6);
				   msiGetContInxFromGenQueryOut(*QueryOut6, *ContInxNew6);
				   *cache = "";
				   *ContInxOld6 = 1;
 				   while(*ContInxOld6 > 0) {
				      foreach (*QueryOut6){
				         msiGetValByKey(*QueryOut6, "RESC_NAME", *cache);
				      }
                                      *ContInxOld6 = *ContInxNew6;
                                      if(*ContInxOld6 > 0) {msiGetMoreRows(*Query6,*QueryOut6,*ContInxNew6)};
                                     }
				   }
				   else {
				   writeLine("stdout", "Failed to copy *FileName from *resourcecontainsthefile to *resourcename");
				   }
				}
			   else {
			        *condition_q5 = "COLL_NAME = '*CollectionName' and DATA_NAME = '*FileName' and RESC_NAME = '*cache'";
      				msiMakeQuery("RESC_NAME, DATA_NAME, DATA_REPL_NUM", *condition_q5, *Query5);
      				msiExecStrCondQuery(*Query5, *QueryOut5);
      				msiGetContInxFromGenQueryOut(*QueryOut5, *ContInx_q5);
				# writeLine("stdout", "ContInx_q5 = *ContInx_q5");
				*replica = 0;
                                foreach (*QueryOut5){
					msiGetValByKey(*QueryOut5, "DATA_REPL_NUM", *replica);
				      # writeLine("stdout", "replNum = *replica")				
				      }
			        if (*debug == "on"){
         		             writeLine("stdout", "source replNum = *replica");
				     writeLine("stdout", "Copy file from *cache to *resourcename");}
			   	*returnresult = msiDataObjRepl(*Path, "destRescName=*resourcename++++rescName=*cache++++replNum=*replica", *Status);
	 		  	 if (*debug == "on"){
				    writeLine("stdout", "returnresult = *returnresult");}
	 		         if (errorcode(*returnresult) >= 0){	
	 	   	      writeLine("stdout", "The file *FileName has been successfully replicated to resource *resourcename");
			         }
				else {
				writeLine("stdout", "Failed to copy *FileName from *cache to *resourcename");
				}	
}			  
	 		      }
	 	     }
	 	   }
	 	}
      if (*debug == "on"){
      	 writeLine("stdout", "The file *FileName will be deleted from cache...");}
      *condition_q5 = "USER_NAME = '*UserName' and DATA_NAME = '*FileName' and RESC_NAME = '*cache'";
      msiMakeQuery("RESC_NAME, DATA_NAME, DATA_REPL_NUM", *condition_q5, *Query5);
      msiExecStrCondQuery(*Query5, *QueryOut5);
      msiGetContInxFromGenQueryOut(*QueryOut5, *ContInx_q5);
      # writeLine("stdout", "ContInx_q5 = *ContInx_q5");
      *cacheexists = 0;
      *replica = 0;
      foreach (*QueryOut5){
		msiGetValByKey(*QueryOut5, "DATA_REPL_NUM", *replica);
		*cacheexists = 1;
		# writeLine("stdout", "replNum = *replica")				
		}
       if (*debug == "on"){
       	  writeLine("stdout", "final replNum = *replica")}
     if (*cacheexists == 1){
      *removeResult = msiDataObjUnlink("objPath=*Path++++replNum=*replica++++forceFlag=", *Status);
      if (errorcode(*removeResult)==0){
      	 if (*debug == "on"){
	    writeLine("stdout", "Successfully remove the file *FileName from disk Cache ...");}
	 }
      else{
	  if (*debug == "on"){
	     writeLine("stdout", "Failed to remove the file *FileName from disk Cache ");}
	}
     }
	 	 
}

input *Path="/osg/home/yaling/hello3.txt", *ResourceGroup="osgSrmGroup", *debug="off"
output ruleExecOut 

