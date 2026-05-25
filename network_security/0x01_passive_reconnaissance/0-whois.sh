#!/bin/bash

domain=$1
output="${domain}.csv"

whois "$domain" | awk '
function val(line,    n, v) {
    n = index(line, ":")
    v = substr(line, n + 1)
    gsub(/^[ \t]+|[ \t]+$/, "", v)
    return v
}

/^Registrant Name:/           { print "Registrant Name,"           val($0) }
/^Registrant Organization:/   { print "Registrant Organization,"   val($0) }
/^Registrant Street:/         { print "Registrant Street,"         val($0) " " }
/^Registrant City:/           { print "Registrant City,"           val($0) }
/^Registrant State\/Province:/{ print "Registrant State/Province," val($0) }
/^Registrant Postal Code:/    { print "Registrant Postal Code,"    val($0) }
/^Registrant Country:/        { print "Registrant Country,"        val($0) }
/^Registrant Phone Ext:/      { print "Registrant Phone Ext:,"     val($0) }
/^Registrant Phone:/          { print "Registrant Phone,"          val($0) }
/^Registrant Fax Ext:/        { print "Registrant Fax Ext:,"       val($0) }
/^Registrant Fax:/            { print "Registrant Fax,"            val($0) }
/^Registrant Email:/          { print "Registrant Email,"          val($0) }

/^Admin Name:/                { print "Admin Name,"                val($0) }
/^Admin Organization:/        { print "Admin Organization,"        val($0) }
/^Admin Street:/              { print "Admin Street,"              val($0) " " }
/^Admin City:/                { print "Admin City,"                val($0) }
/^Admin State\/Province:/     { print "Admin State/Province,"      val($0) }
/^Admin Postal Code:/         { print "Admin Postal Code,"         val($0) }
/^Admin Country:/             { print "Admin Country,"             val($0) }
/^Admin Phone Ext:/           { print "Admin Phone Ext:,"          val($0) }
/^Admin Phone:/               { print "Admin Phone,"               val($0) }
/^Admin Fax Ext:/             { print "Admin Fax Ext:,"            val($0) }
/^Admin Fax:/                 { print "Admin Fax,"                 val($0) }
/^Admin Email:/               { print "Admin Email,"               val($0) }

/^Tech Name:/                 { print "Tech Name,"                 val($0) }
/^Tech Organization:/         { print "Tech Organization,"         val($0) }
/^Tech Street:/               { print "Tech Street,"               val($0) " " }
/^Tech City:/                 { print "Tech City,"                 val($0) }
/^Tech State\/Province:/      { print "Tech State/Province,"       val($0) }
/^Tech Postal Code:/          { print "Tech Postal Code,"          val($0) }
/^Tech Country:/              { print "Tech Country,"              val($0) }
/^Tech Phone Ext:/            { print "Tech Phone Ext:,"           val($0) }
/^Tech Phone:/                { print "Tech Phone,"                val($0) }
/^Tech Fax Ext:/              { print "Tech Fax Ext:,"             val($0) }
/^Tech Fax:/                  { print "Tech Fax,"                  val($0) }
/^Tech Email:/                { print "Tech Email,"                val($0) }
' > "$output"
