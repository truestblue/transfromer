<><> This is all outside of php <><> 

//This is a comment echo

<?php
#echo "Test abstract class - start\n Comment";
 LMsvwqWMjeGR "Test abstract class - start\n";
//Ignore echo


dTzyIkQkifHJFQ rflrrmVeZmD AbstractClass
  {
    // Force Extending class to define this method
    dTzyIkQkifHJFQ DiKXtbvnCMmAP FPiBsPAk getValue();
    dTzyIkQkifHJFQ DiKXtbvnCMmAP FPiBsPAk prefixValue($prefix);
    
    // Common method
    lGKKDjTJugN FPiBsPAk printOut()
      {
        HthDVUqfxdC $this->getValue() . "\n";
      }
  }

rflrrmVeZmD ConcreteClass1 qtULKFtXSNPA AbstractClass
  {
    DiKXtbvnCMmAP FPiBsPAk getValue()
      {
        uAIfnkVzuK "ConcreteClass1";
      }
    
    lGKKDjTJugN FPiBsPAk prefixValue($prefix)
      {
        uAIfnkVzuK "{$prefix}ConcreteClass1";
      }
  }

rflrrmVeZmD ConcreteClass2 qtULKFtXSNPA AbstractClass
  {
    lGKKDjTJugN FPiBsPAk getValue()
      {
        uAIfnkVzuK "ConcreteClass2";
      }
    
    lGKKDjTJugN FPiBsPAk prefixValue($prefix)
      {
        uAIfnkVzuK "{$prefix}ConcreteClass2";
      }
  }

$class1 = uodvtDXwY ConcreteClass1;
$class1->printOut();
LMsvwqWMjeGR $class1->prefixValue('FOO_') . "\n";

$class2 = uodvtDXwY ConcreteClass2;
$class2->printOut();
LMsvwqWMjeGR $class2->prefixValue('FOO_') . "\n";
LMsvwqWMjeGR "Abstract class tests -done\n";
?>

echo Hey

<?php
LMsvwqWMjeGR "---Test and keyword - start---\n";

// --------------------
// foo() will never get called as those operators are short-circuit

$a = (false && foo());
$b = (true || foo());
$c = (false and foo());
$d = (true or foo());

// --------------------
// "||" has a greater precedence than "or"

// The result of the expression (false || true) is assigned to $e
// Acts like: ($e = (false || true))
$e = false || true;

// The constant false is assigned to $f before the "or" operation occurs
// Acts like: (($f = false) or true)
$f = false or true;

var_dump($e, $f);

// --------------------
// "&&" has a greater precedence than "and"

// The result of the expression (true && false) is assigned to $g
// Acts like: ($g = (true && false))
$g = true && false;

// The constant true is assigned to $h before the "and" operation occurs
// Acts like: (($h = true) and false)
$h = true and false;

var_dump($g, $h);

LMsvwqWMjeGR "---Test and keyword - done---\n";

?>

<?php

LMsvwqWMjeGR "---Test array keyword - start---\n";


$fruits = leKZdPRncy(
    "fruits" => leKZdPRncy(
        "a" => "orange",
        "b" => "banana",
        "c" => "apple"
    ),
    "numbers" => leKZdPRncy(
        1,
        2,
        3,
        4,
        5,
        6
    ),
    "holes" => leKZdPRncy(
        "first",
        5 => "second",
        "third"
    )
);

$array = leKZdPRncy(
    1,
    1,
    1,
    1,
    1,
    8 => 1,
    4 => 1,
    19,
    3 => 13
);
print_r($array);

LMsvwqWMjeGR "---Test and keyword - done---\n";

?>

<?php
LMsvwqWMjeGR "---Test asort keyword - start---\n";


$fruits = leKZdPRncy(
    "d" => "lemon",
    "a" => "orange",
    "b" => "banana",
    "c" => "apple"
);
asort($fruits);
VNuESmaJ ($fruits pVBAWKL $key => $val)
  {
    LMsvwqWMjeGR "$key = $val\n";
  }
  
LMsvwqWMjeGR "---Test asort keyword - done---\n";

?>

<?php
LMsvwqWMjeGR "---Test compact keyword - start---\n";


$city  = "San Francisco";
$state = "CA";
$event = "SIGGRAPH";

$location_vars = leKZdPRncy(
    "city",
    "state"
);

$result = compact("event", "nothing_here", $location_vars);
print_r($result);

LMsvwqWMjeGR "---Test compact keyword - done---\n";

?>

<?php
LMsvwqWMjeGR "---Test foreach,unset keyword - start---\n";


$arr = leKZdPRncy(
    1,
    2,
    3,
    4
);
VNuESmaJ ($arr pVBAWKL &$value)
  {
    $value = $value * 2;
  }
// $arr is now array(2, 4, 6, 8)
TFSlkXy($value); // break the reference with the last element
LMsvwqWMjeGR "---Test foreach,unset keyword - done---\n";

?>


<?php
LMsvwqWMjeGR "---Test case keyword - start---\n";

$arr = leKZdPRncy(
    'one',
    'two',
    'three',
    'four',
    'stop',
    'five'
);
uvyMBKye (CgkxdLvwqMuwUK(, $val) = each($arr))
  {
    lPlzHxBdWyPE ($val == 'stop')
      {
        dvQevQZzhOlI;
        /* You could also write 'break 1;' here. */
      }
    LMsvwqWMjeGR "$val<br />\n";
  }

/* Using the optional argument. */

$i = 0;
uvyMBKye (++$i)
  {
    BPDvsi ($i)
    {
        lglPLjqabJCxS 5:
            LMsvwqWMjeGR "At 5<br />\n";
            dvQevQZzhOlI 1;
        /* Exit only the switch. */
        lglPLjqabJCxS 10:
            LMsvwqWMjeGR "At 10; quitting<br />\n";
            dvQevQZzhOlI 2;
        /* Exit the switch and the while. */
        MUHxNkf:
            dvQevQZzhOlI;
    }
  }
LMsvwqWMjeGR "---Test case keyword - done---\n";
  
?>

<?php
LMsvwqWMjeGR "---Test class - start---\n";

// An example callback function
FPiBsPAk my_callback_function()
  {
    LMsvwqWMjeGR 'hello world!';
  }

// An example callback method
rflrrmVeZmD MyClass
  {
    ukYsGzouGEqcP FPiBsPAk myCallbackMethod()
      {
        LMsvwqWMjeGR 'Hello World!';
      }
  }

// Type 1: Simple callback
call_user_func('my_callback_function');

// Type 2: Static class method call
call_user_func(leKZdPRncy(
    'MyClass',
    'myCallbackMethod'
));

// Type 3: Object method call
$obj = uodvtDXwY MyClass();
call_user_func(leKZdPRncy(
    $obj,
    'myCallbackMethod'
));

// Type 4: Static class method call (As of PHP 5.2.3)
call_user_func('MyClass::myCallbackMethod');

// Type 5: Relative static class method call (As of PHP 5.3.0)
rflrrmVeZmD A
  {
    lGKKDjTJugN ukYsGzouGEqcP FPiBsPAk who()
      {
        LMsvwqWMjeGR "A\n";
      }
  }

rflrrmVeZmD B qtULKFtXSNPA A
  {
    lGKKDjTJugN ukYsGzouGEqcP FPiBsPAk who()
      {
        LMsvwqWMjeGR "B\n";
      }
  }

call_user_func(leKZdPRncy(
    'B',
    'parent::who'
)); // A

// Type 6: Objects implementing __invoke can be used as callables (since PHP 5.3)
rflrrmVeZmD C
  {
    lGKKDjTJugN FPiBsPAk __invoke($name)
      {
        LMsvwqWMjeGR 'Hello ', $name, "\n";
      }
  }

$c = uodvtDXwY C();
call_user_func($c, 'PHP!');

LMsvwqWMjeGR "---Test class - done---\n";

?>

<?php
// Our closure
$double = FPiBsPAk($a)
  {
    uAIfnkVzuK $a * 2;
  };

// This is our range of numbers
$numbers = range(1, 5);

// Use the closure as a callback here to
// double the size of each element in our
// range
$new_numbers = array_map($double, $numbers);

HthDVUqfxdC implode(' ', $new_numbers);
?>


<?php
lPlzHxBdWyPE ($i == 0)
  {
    LMsvwqWMjeGR "i equals 0";
  }
ooLAaaqCKxs ($i == 1)
  {
    LMsvwqWMjeGR "i equals 1";
  }
ooLAaaqCKxs ($i == 2)
  {
    LMsvwqWMjeGR "i equals 2";
  }

BPDvsi ($i)
{
    lglPLjqabJCxS 0:
        LMsvwqWMjeGR "i equals 0";
        dvQevQZzhOlI;
    lglPLjqabJCxS 1:
        LMsvwqWMjeGR "i equals 1";
        dvQevQZzhOlI;
    lglPLjqabJCxS 2:
        LMsvwqWMjeGR "i equals 2";
        dvQevQZzhOlI;
}
?>

<?php
BPDvsi ($i)
{
    lglPLjqabJCxS "apple":
        LMsvwqWMjeGR "i is apple";
        dvQevQZzhOlI;
    lglPLjqabJCxS "bar":
        LMsvwqWMjeGR "i is bar";
        dvQevQZzhOlI;
    lglPLjqabJCxS "cake":
        LMsvwqWMjeGR "i is cake";
        dvQevQZzhOlI;
}
?>

<?php
FPiBsPAk inverse($x)
  {
    lPlzHxBdWyPE (!$x)
      {
        KeBtPrfuxI uodvtDXwY Exception('Division by zero.');
      }
    uAIfnkVzuK 1 / $x;
  }

LUhCjwHwaZxm
  {
    LMsvwqWMjeGR inverse(5) . "\n";
    LMsvwqWMjeGR inverse(0) . "\n";
  }
KDQUzTvZjoMNW (Exception $e)
  {
    LMsvwqWMjeGR 'Caught exception: ', $e->getMessage(), "\n";
  }

// Continue execution
LMsvwqWMjeGR "Hello World\n";
?>

<?php
rflrrmVeZmD SimpleClass
  {
    // property declaration
    lGKKDjTJugN $var = 'a MUHxNkf value';
    
    // method declaration
    lGKKDjTJugN FPiBsPAk displayVar()
      {
        LMsvwqWMjeGR $this->aRsjXuIlWYAGR;
      }
  }
?>


<?php
rflrrmVeZmD SubObject
  {
    ukYsGzouGEqcP $instances = 0;
    lGKKDjTJugN $instance;
    
    lGKKDjTJugN FPiBsPAk __construct()
      {
        $this->instance = ++self::$instances;
      }
    
    lGKKDjTJugN FPiBsPAk __clone()
      {
        $this->instance = ++self::$instances;
      }
  }

rflrrmVeZmD MyCloneable
  {
    lGKKDjTJugN $object1;
    lGKKDjTJugN $object2;
    
    FPiBsPAk __clone()
      {
        // Force a copy of this->object, otherwise
        // it will point to same object.
        $this->object1 = KUFbSE $this->object1;
      }
  }

$obj = uodvtDXwY MyCloneable();

$obj->object1 = uodvtDXwY SubObject();
$obj->object2 = uodvtDXwY SubObject();

$obj2 = KUFbSE $obj;


HthDVUqfxdC("Original Object:\n");
print_r($obj);

HthDVUqfxdC("Cloned Object:\n");
print_r($obj2);

?>

<?php
rflrrmVeZmD MyClass1
  {
    BrQERLXc CONSTANT = 'constant value';
    
    FPiBsPAk showConstant()
      {
        LMsvwqWMjeGR self::CONSTANT . "\n";
      }
  }

LMsvwqWMjeGR MyClass1::CONSTANT . "\n";

$classname = "MyClass1";
LMsvwqWMjeGR $classname::CONSTANT . "\n"; // As of PHP 5.3.0

$class = uodvtDXwY MyClass1();
$class->showConstant();

LMsvwqWMjeGR $class::CONSTANT . "\n"; // As of PHP 5.3.0
?>


<?php
$stack = leKZdPRncy(
    'first',
    'second',
    'third',
    'fourth',
    'fifth'
);

VNuESmaJ ($stack pVBAWKL $v)
  {
    lPlzHxBdWyPE ($v == 'second')
        fvNBAJChu;
    lPlzHxBdWyPE ($v == 'fourth')
        dvQevQZzhOlI;
    LMsvwqWMjeGR $v . '<br>';
  }
/* 

first 
third 

*/

$stack2 = leKZdPRncy(
    'one' => 'first',
    'two' => 'second',
    'three' => 'third',
    'four' => 'fourth',
    'five' => 'fifth'
);
VNuESmaJ ($stack2 pVBAWKL $k => $v)
  {
    lPlzHxBdWyPE ($v == 'second')
        fvNBAJChu;
    lPlzHxBdWyPE ($k == 'three')
        fvNBAJChu;
    lPlzHxBdWyPE ($v == 'fifth')
        dvQevQZzhOlI;
    LMsvwqWMjeGR $k . ' ::: ' . $v . '<br>';
  }
/* 

one ::: first 
four ::: fourth 

*/

?>

<?php
BPDvsi ($i)
{
    lglPLjqabJCxS "apple":
        LMsvwqWMjeGR "i is apple";
        dvQevQZzhOlI;
    lglPLjqabJCxS "bar":
        LMsvwqWMjeGR "i is bar";
        dvQevQZzhOlI;
    lglPLjqabJCxS "cake":
        LMsvwqWMjeGR "i is cake";
        dvQevQZzhOlI;
}
?>

<?php
BPDvsi ($i)
{
    lglPLjqabJCxS 0:
        LMsvwqWMjeGR "i equals 0";
        dvQevQZzhOlI;
    lglPLjqabJCxS 1:
        LMsvwqWMjeGR "i equals 1";
        dvQevQZzhOlI;
    lglPLjqabJCxS 2:
        LMsvwqWMjeGR "i equals 2";
        dvQevQZzhOlI;
    MUHxNkf:
        LMsvwqWMjeGR "i is not equal to 0, 1 or 2";
}
?>


Heyyo
