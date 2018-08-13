#!/usr/bin/perl
######################################################################
# verify_resource_usage.pl
######################################################################
# run like this:
#    perl VerifyResourceUsage.pl
# to discover 
#    1) what LogMessages.cs strings are unused
#    2) whether any of the string IDs and string value prefixes don't match
#    3) whether any LogMessages.cs files contain duplicate IDs

use strict;
use strict 'subs';
use strict 'vars';
use strict 'refs';
use Cwd;
use Data::Dumper;
use File::Find;
use File::Basename;

# TODO the script doesn't know about comments and #if, so it can have false-positives on commented-out code...

my $PERF_DEBUG = (1==0); # print debug info to screen, so a human watching output in real time can see where time spent
my $ERRORS_ONLY_MODE = (1==0);  # only print serious errors
my $THERE_ARE_ERRORS = (1==0);
# prefix strings so build won't filter messages
my $ERROR = "verify_resource_usage.pl(): error";
my $WARN = "verify_resource_usage.pl(): warning";
my $TELL = "BUILDMSG:";
my $EXITCODE = 0;

my $CROP_FILE_PATH_AT = "src";

######################################################################
sub PrintError($)
{
    my $s = shift;
    $EXITCODE = -1;
    if ($ERRORS_ONLY_MODE)
    {
        print "$ERROR $s";
        $THERE_ARE_ERRORS = 1;
    }
    else
    {
        print "$s";
    }
}

sub PrintWarn($)
{
    my $s = shift;
    if ($ERRORS_ONLY_MODE)
    {
        print "$WARN $s";
    }
    else
    {
        print "$s";
    }
}

sub Print($)
{
    my $s = shift;
    if ($ERRORS_ONLY_MODE)
    {
        # do nothing, this is just informational
    }
    else
    {
        print "$s";
    }
}

sub PrintPerf($)
{
    my $s = shift;
    if ($PERF_DEBUG)
    {
        print "$s";
    }
}

######################################################################

# Each format item takes the following form.
#
# {index[,alignment][:formatString]}
#
# The matching braces ("{" and "}") are required. Because opening and closing braces are interpreted as 
# starting and ending a format item, you must specify two opening braces ("{{") in the fixed text to 
# display one opening brace ("{"), and specify two closing braces ("}}") in the fixed text to display 
# one closing brace ("}").

my $FORMAT_STR_ARG = qr/
                        (?<!{)         # not preceded by {
                        \{              # {
                        (\d+)          # arg# SAVED IN $1
                        (?:,-?\d+)?    # optional alignment (signed integer)
                        (?::[^}]*)?    # optional formatString
                        }              # }
                        /ox;

sub CountArgs($$)
{
    my $id = shift;
    my $formatStr = shift;
    my %argNums;
    if ($formatStr =~ /$FORMAT_STR_ARG/)
    {
        while ($formatStr =~ /$FORMAT_STR_ARG/g)
        {
            my $argNum = $1;
#print "argNum=$argNum\n";
            $argNums{$argNum} = 1;
        }
        my @argNums = sort keys %argNums;
        my $numArgs = scalar(@argNums);
        if ($argNums[-1] != ($numArgs-1))
        {
            PrintError("\n");
            PrintError("$id doesn't use arguments properly: $formatStr\n");
        }
#print "$id has $numArgs\n";
        return $numArgs;
    }
    else
    {
#print "$id has 0\n";
        return 0;
    }
}

######################################################################

sub CountActualArgs($)
{
    my $args = shift;
    my $origArgs = $args;
    return 0 if $args =~ /^\s*\)/;
    my $count = 1;   # there's at least one arg
    my $depth = 0;
    for(;;)
    {
        $args =~ s/^[^(),]*(.)//;  # strip off chars we don't care about
        my $interestingChar = $1;
        if ($interestingChar eq "(")
        {
            $depth++;
        }
        elsif ($interestingChar eq ")")
        {
            return $count if ($depth == 0);
            $depth--;
        }
        elsif ($interestingChar eq ",")
        {
            $count++ if ($depth == 0);   # each time we see a ',' at the top level, there's one more arg
        }
        else
        {
            print "\nuh oh, about to die, input was '$origArgs'\n";
            die "you can never get here";
        }
    }
}

sub PrintBadArgCount($$$$$$)
{
    my $fileName = shift;
    my $id = shift;
    my $numArgsExpected = shift;
    my $numArgsFound = shift;
    my $getstringCall = shift;
    my $resource = shift;
    PrintError("\n");
    PrintError("\n");
    PrintError("In file $fileName,\n");
    PrintError("    GetString call with $id has wrong # of args (expected $numArgsExpected, found $numArgsFound)\n");
    PrintError("Here is the call: $getstringCall\n");
    PrintError("And by the way, $id=\"$resource\"\n");
}

sub VerifyNumBraces($$)
{
    my $id = shift;
    my $formatString = shift;
    my @braces;

    foreach my $char (split //, $formatString) {
        if($char eq "{") {
            push @braces, $char
        } elsif ($char eq "}") {
            if (@braces == 0) {
                PrintError("The following format string has mismatching braces.\n");
                PrintError("$id =$formatString\n");
                return;
            } else {
                pop @braces
            }
        }
    }

    if (@braces != 0) {
          PrintError("The following format string has mismatching braces.\n");
          PrintError("$id = $formatString\n");
    }
}

######################################################################

sub EnsureArgCountCorrect($$$$$$)
{
    my $prefix = shift;
    my $getstringCall = shift;
    my $numArgsExpected = shift;
    my $id = shift;
    my $fileName = shift;
    my $resource = shift;

#print "\nID = $id  GSC = $getstringCall\n";
    $getstringCall =~ /$prefix$id\s*,?((?:.|\n)*)/;
    my $restArgs = $1;
    my $count = CountActualArgs($restArgs);
#print "\n$count in $restArgs\n";
    if ($numArgsExpected != $count)
    {
        PrintBadArgCount($fileName, $id, $numArgsExpected, $count, $getstringCall, $resource);
    }
}

######################################################################
# Main 

#get all the directories that we need to check LogMessages.cs for
my $dir = getcwd;

# will store the file names for each directory
my @filenames;

# will store the ids for each directory
my %dirhash;

my @directories;

sub FindDirs {
    my $file = $_;
    return unless -f $file;
    my $fullpath = $File::Find::name;
    if ($file =~ /LogMessages.cs$/) {
        my $directory = dirname($fullpath);    
        push @directories, $directory;
    }
}

find(\&FindDirs, $dir);

foreach my $directory (@directories) 
{
    my $resources_txt = $directory . "/LogMessages.cs";
    PrintPerf("\nPERF: starting script\n");
    PrintPerf("\nPERF: Analyzing file: $resources_txt\n");

    Print("$resources_txt\n\n");
    open(RES, "< $resources_txt") or die "can't open $resources_txt: $!";

    my %ids;   # key is identifier, value is a tuple: [# references in code, number of formatString args, the resource string itself]

    PrintPerf("\nPERF: reading resources\n");

    while (<RES>)
    {
        next if /^;/;    # lines starting with ';' are comments
        next if /^#/;    # lines starting with '#' are comments
        next if /\/\//;  # lines starting with '//' are comments
        next if not /internal const string (\w*?)\s*=(.*)/;   
        my $id = $1;     # identifier is everything up to '='
        my $value = $2;  # rest is actual resource string value

        my $numArgs = CountArgs($id, $value);
        VerifyNumBraces($id, $value);
        $ids{$id} = [0,$numArgs,$value];
        # go through each directory that we've processed so far
        foreach my $directory2 (keys(%dirhash))
        {
            # checking for duplicate ids in the same directory is unnecessary
            if (not $directory eq $directory2) {
                if (grep {$_ eq $id} @{$dirhash{$directory2}}) 
                {
                    PrintError("\nSame id ($id) is reused in the LogMessages.cs file of both: \n $directory \n and \n $directory2 \n \n");  
                } 
            }
        }
        push @{$dirhash{$directory}}, $id;
    }

    PrintPerf("\nPERF: checking string id values\n");
    foreach my $id (keys(%ids))
        {
            my $length = length($id); # get length of the id
            my $stringvalue = substr ($ids{$id}[2], 2); # remove quote char at start of string
            my $stringid = substr($stringvalue, 0, $length); # get prefix of string value
            if (not $id eq $stringid) 
            {
                PrintError("string name ($id) is not the same as it's value: $stringid \n \n");
            }
            
        }

    PrintPerf("\nPERF: done reading resources\n");
    close(RES) or die "can't close $resources_txt: $!";

    PrintPerf("\nPERF: Open Files\n");

    @filenames = ();

    sub FindFilenames {
        my $file = $_;
        return unless -f $file;
        my $fullpath = $File::Find::name;
        if ($file =~ /(.)+.cs$/) {
            push @filenames, $fullpath;
        }
    }

    find(\&FindFilenames, $directory);

    PrintPerf("\nPERF: reading and processing source files\n");
    foreach my $file (@filenames)
    {
        $file =~ /$CROP_FILE_PATH_AT(.*)/;
        my $shortFileName = $1;

        open(FIL, "< $file") or die "can't open $file: $!";
    
        my $filestring;
        {
            local $/; # slurp
            $filestring = <FIL>; #slurp!
        }
        close(FIL) or die "can't close $file: $!";

        # find all call sites and EnsureArgCountCorrect
        my $rest = $filestring;

        while ($rest =~ /LogMessages\.(\w+)/g)
        {   
            my $id = $1;

            if (defined $ids{$id})   # sometimes there will be commented-out code with LogMessages.ThisIDDoesntExistAnymore
            {
                $ids{$id}[0]++;   # increment number-references-to-this-id
            }
        }
    }

    PrintPerf("\nPERF: done reading and processing source files\n");
    {
        PrintPerf("\nDone processing files\n");

        my $numUnreferencedIds = 0;
        foreach my $id (keys(%ids))
        {
            my $n = $ids{$id}[0];
            if ($n == 0)
            {
                PrintError("$id was referenced in $n files\n");
                $numUnreferencedIds++;
            }
        }
        Print("\n$numUnreferencedIds identifiers were unreferenced\n\n");
    }

    if ($ERRORS_ONLY_MODE and $THERE_ARE_ERRORS)
    {
        PrintError("\n");
        PrintError("There were errors checking ProperUsage of resources.txt!\n");
        PrintError("You must fix the above errors before you can build.\n");
        PrintError("See ndp\\indigo\\tools\\Resources\\ProperUsage\\README.txt for details if you need help.\n");
        exit 1;
    }

    Print("--------------\n\n");
}

exit $EXITCODE;
