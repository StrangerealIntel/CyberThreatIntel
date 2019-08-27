 $a = $args[0];
 $mod=$args[1];
 $res=@()

     switch ($mod) {
        1   { $b = $a.ToCharArray();
            $c=""
            Foreach ($element in $b) {$c = $c + " " + [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($element))}
            $c = ( ($c -join "").split() )
            $c=$c[1..($c.length -1)]
            for($i=0;$i -lt $c.length ;$i++)
            {
                $tmp=$c[$i] 
                $tmp=[Convert]::ToInt64($tmp,16) -1
                $tmp= '{0:X}' -f $tmp
                $tmp= [char][byte]"0x$tmp"
                $res+=$tmp
            }
            break}
        2   { $b = $a.ToCharArray();
            $c=""
            Foreach ($element in $b) {$c = $c + " " + [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($element))}
            $c = ( ($c -join "").split() )
            $c=$c[1..($c.length -1)]
            for($i=0;$i -lt $c.length ;$i++)
            {
                $tmp=$c[$i] 
                $tmp=([Convert]::ToInt64($tmp,16) -3) -band 0xFF
                $tmp= '{0:X}' -f $tmp
                $tmp= [char][byte]"0x$tmp"
                $res+=$tmp
            }
            break}
        3   {
            $counter=0
            $dat=@()
            for($i=0; $i -lt $a.length; $i++)
            { 
                if($counter -eq 2)
                    {
                        $counter =0; 
                        $dat+= " ";
                        $dat+=$a[$i]
                    } 
                    else {$dat+=$a[$i]} 
                    $counter++;
            } 
            $t=($dat -join "").split(" ")
            for($i=0; $i -lt $t.length; $i++)
            {
                $tmp=([Convert]::ToInt64($t[$i],16) -13) -band 0xFF
                $tmp= '{0:X}' -f $tmp
                $tmp= [char][byte] "0x$tmp"
                $res+=$tmp
            }
            break}
        default {write-host "Invalid mod" -ForegroundColor "Red"; exit}
    
 }
 $res -join ""


