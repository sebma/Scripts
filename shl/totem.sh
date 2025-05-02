#!/bin/sh

TOTEM_VERSION=3.1
#TOTEM_HOMEDIR=/usr/local/share/totem
TOTEM_HOMEDIR=$HOME/REOP/TP/totem
LIBRARYPATH=$TOTEM_HOMEDIR/lib/
EXTDIRS=$TOTEM_HOMEDIR/lib/java

#JVMARGS="-d32 -Xmx512m"
JVMARGS="-Xmx512m"
#JVMARGS="-verbose:jni -Xcheck:jni -Xmx512m"

if [ -z "$JAVA_HOME" ]; then
    JAVA=`which java`
else
    JAVA=$JAVA_HOME/bin/java
fi

if [ ! -f "$JAVA" ]; then
    echo "Java executable not found ($JAVA). Abording."
    exit 0
fi

if [ ! -x "$JAVA" ]; then 
    echo "Java executable not found ($JAVA). (Not executable). Abording."
    exit 0
fi


#echo "$JAVA $JVMARGS -Djava.ext.dirs=$EXTDIRS -Djava.library.path=$LIBRARYPATH -jar $TOTEM_HOMEDIR/dist/totem-$TOTEM_VERSION.jar $@"
LD_LIBRARY_PATH=$LIBRARYPATH:$LD_LIBRARY_PATH $JAVA $JVMARGS -Djava.ext.dirs=$EXTDIRS -Djava.library.path=$LIBRARYPATH -jar $TOTEM_HOMEDIR/dist/totem-$TOTEM_VERSION.jar $@

