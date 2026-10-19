fn main(){
  let path=std::env::args().nth(1).unwrap();
  let d=std::fs::read(&path).unwrap();
  let p=ariados::formats::parse(&d).unwrap();
  for o in &p.objects {
    println!("=== arch {} ===", o.arch.label());
    let g=ariados::graph::build(o);
    for f in g.functions.values(){
      if f.strings.is_empty()&&f.imports.is_empty()&&f.calls.is_empty(){continue;}
      println!("fn {} @ {:#x}", f.name, f.addr);
      for s in &f.strings { println!("   str: {:?}", s); }
      for i in &f.imports { println!("   imp: {}", i); }
      for c in &f.calls { println!("   call: {}", g.name_of(*c)); }
    }
  }
}
