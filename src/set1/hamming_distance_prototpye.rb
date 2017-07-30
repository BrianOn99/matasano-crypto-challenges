# As the question states that "We get more tech support questions for this challenge", I quickly
# wrote a prototype in ruby for calculating hamming distance.  Quite starightforward.

def hamming_distance(a, b)
  a_bits = a.each_byte.map {|x| "%08i" % (x.to_s 2)}.join
  b_bits = b.each_byte.map {|x| "%08i" % (x.to_s 2)}.join
  a_bits.each_byte.zip(b_bits.each_byte).count {|x,y| x!=y}
end

puts hamming_distance("this is a test", "wokka wokka!!!")
