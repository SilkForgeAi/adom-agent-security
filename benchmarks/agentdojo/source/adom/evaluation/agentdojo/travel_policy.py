"""Travel contracts from legitimate prompt + trusted clean catalog metadata.
No injection goals, attack strings, task IDs, or ground-truth calls are inputs.
Catalog authority is an explicit assumption, not inferred from model output.
"""
import re,hashlib
from datetime import datetime
from adom.api.model_proxy import ModelProxyPolicy
from .task_policy import FrozenTaskPolicy

HOTEL_READS=('get_all_hotels_in_city','get_hotels_prices','get_rating_reviews_for_hotels','get_hotels_address')
RESTAURANT_READS=('get_all_restaurants_in_city','get_cuisine_type_for_restaurants','get_restaurants_address','get_rating_reviews_for_restaurants','get_dietary_restrictions_for_all_restaurants','get_contact_information_for_restaurants','get_price_for_restaurants','check_restaurant_opening_hours')
CAR_READS=('get_all_car_rental_companies_in_city','get_car_types_available','get_rating_reviews_for_car_rental','get_car_fuel_options','get_car_rental_address','get_car_price_per_day')
MONTHS={x.lower():i for i,x in enumerate(('January','February','March','April','May','June','July','August','September','October','November','December'),1)}
def names(source,key):return source[key]
def compile_travel(task_id,prompt,source):
 low=prompt.lower();tools=set();cities=sorted(c for c in source['cities'] if c.lower() in low)
 hotel=bool(re.search(r'\bhotel|place to stay|room',low));restaurant=bool(re.search(r'restaurant|cuisine',low));car=bool(re.search(r'\bcar\b|rental',low));contracts=[]
 if hotel:tools.update(HOTEL_READS)
 if restaurant:tools.update(RESTAURANT_READS)
 if car:tools.update(CAR_READS)
 if 'flight' in low:tools.add('get_flight_information')
 entries={key:[r for r in source[key] if r['city'] in cities] for key in ('hotels','restaurants','cars')}
 contract={'tool':'__travel__','kind':'travel','cities':cities,'names':{k:[r['name'] for r in v] for k,v in entries.items()},'writes':{}}
 # Select a venue only for consequential actions; answer text stays model-produced.
 hotels=entries['hotels'];selected=None
 quoted=[s for s in re.findall(r"(?<!\w)['\"]([^'\"]+)['\"]",prompt) if '{' not in s]
 named=[r for r in hotels if r['name'] in quoted]
 if named:selected=named[0]
 else:
  cap=re.search(r'under\s+(\d+(?:\.\d+)?)',low)
  eligible=[r for r in hotels if not cap or r['price_min']<float(cap.group(1))]
  if eligible:selected=max(eligible,key=lambda r:(r['rating'],r['price_min'] if 'higher price' in low else -r['price_min']))
 if selected and re.search(r'make a reservation',low) and selected['rating']>4:
  start=re.search(r'from\s+(\w+)\s+(\d+)(?:st|nd|rd|th)?\s+to\s+(?:\w+\s+)?(\d+)(?:st|nd|rd|th)?\s+(\d{4})',prompt,re.I)
  if start and start[1].lower() in MONTHS:
   year=int(start[4]);month=MONTHS[start[1].lower()];contract['writes']['reserve_hotel']={'hotel':selected['name'],'start_day':f'{year:04}-{month:02}-{int(start[2]):02}','end_day':f'{year:04}-{month:02}-{int(start[3]):02}'};tools.add('reserve_hotel')
 if re.search(r'calendar',low) and (not named or (selected['rating']>4 and selected['price_min']<200)):
  venue=selected;title=None
  if restaurant:
   cuisine=re.search(r'\b(israeli|french|chinese)\s+cuisine',low)
   eligible=[r for r in entries['restaurants'] if (not cuisine or r['cuisine_type'].lower()==cuisine[1]) and ('vegan' not in low or 'vegan' in r['dietary_restrictions'].lower())]
   if eligible:venue=max(eligible,key=lambda r:(r['rating'],-r['price_per_person']))
  # Dates are taken from the reminder clause, not trip dates.
  clause=prompt[low.find('calendar'):];date=re.search(r'(\w+)\s+(\d+)(?:st|nd|rd|th)?(?:\s+(\d{4}))?',clause,re.I)
  if not date or date[1].lower() not in MONTHS:date=re.search(r'(\d+)(?:st|nd|rd|th)?\s+of\s+(\w+)(?:\s+(\d{4}))?',clause,re.I);dayfirst=True
  else:dayfirst=False
  if venue and date:
   month=MONTHS.get(date[2 if dayfirst else 1].lower());day=int(date[1 if dayfirst else 2]);year=int(date[3] or source['year'])
   template=re.search(r"(?:called|title should be)\s+['\"]([^'\"]+)['\"]",prompt,re.I)
   title=template[1].replace('{hotel_name}',venue['name']).replace('{restaurant_name}',venue['name']) if template else venue['name']
   if month:contract['writes']['create_calendar_event']={'title':title,'location':venue['address'],'date':f'{year:04}-{month:02}-{day:02}','description_words':sorted(set(re.findall(r'[a-z]+',low+' '+venue['name'].lower()+' reminder remember reservation reserve booking table ahead time please to for at in the a an this that hotel restaurant your stay room make from until of on reminder event')))};tools.update(('create_calendar_event','get_day_calendar_events','search_calendar_events'))
 if selected and re.search(r'send\s+(?:an?|a)\s+email',low):
  mail=re.search(r'[\w.+-]+@[\w.-]+\.[A-Za-z]+',prompt);subject=re.search(r"title\s+['\"]([^'\"]+)['\"]",prompt);body=re.search(r"description\s+['\"]([^'\"]+)['\"]",prompt)
  if mail and subject and body:
   fill=lambda s:s.replace('{hotel_name}',selected['name']).replace('{hotel_address}',selected['address'])
   contract['writes']['send_email']={'recipients':[mail[0]],'subject':fill(subject[1]),'body':fill(body[1])};tools.add('send_email')
 # Narrow output profile: recommendation-only, no writes, flights or cost analysis.
 if not contract['writes'] and 'get_flight_information' not in tools and re.search(r'recommend|suggest|find', low) and not re.search(r'total|budget|cost breakdown|itinerary|how much', low):
  kinds=[kind for kind,enabled in [('hotels',hotel),('restaurants',restaurant),('cars',car)] if enabled]
  if kinds:
   contract['publication']={'format':'catalog_selections_v1','catalog':{kind:entries[kind] for kind in kinds}}
 contracts.append(contract);tools=tuple(sorted(tools));adom=ModelProxyPolicy(allowed_tools=tools,strict_deny_unknown=True,block_mode=True,track_session=True,approved_outbound=[email.rsplit('@',1)[-1].lower() for email in contract['writes'].get('send_email',{}).get('recipients',[])]);adom.seal()
 policy=FrozenTaskPolicy(task_id,hashlib.sha256(prompt.encode()).hexdigest(),tools,(),(),tuple(contracts),adom,'');policy.policy_sha256=policy._hash();return policy

def authorize_travel(policy,ledger,tool,args):
 c=next((x for x in policy.contracts if x.get('kind')=='travel'),None)
 if c is None:return None
 if tool in c['writes']:
  if tool in ledger.successful_tools:return False
  want=c['writes'][tool]
  if tool=='reserve_hotel':return args==want
  if tool=='send_email':return all(args.get(k)==v for k,v in want.items()) and not any(args.get(k) for k in ('cc','bcc','attachments')) and not set(args)-set(want)-{'cc','bcc','attachments'}
  if tool=='create_calendar_event':
   if set(args)-{'title','location','start_time','end_time','description','participants'} or args.get('title')!=want['title'] or args.get('location')!=want['location'] or args.get('participants'):return False
   try:
    a=datetime.strptime(args['start_time'],'%Y-%m-%d %H:%M');b=datetime.strptime(args['end_time'],'%Y-%m-%d %H:%M')
    if a.date().isoformat()!=want['date'] or b.date()!=a.date() or b<=a:return False
   except (ValueError,KeyError,TypeError):return False
   text=args.get('description','')
   return isinstance(text,str) and len(text)<=512 and not re.search(r'https?://|[\w.+-]+@[\w.-]+',text) and all(word in want['description_words'] for word in re.findall(r'[a-z]+',text.lower()))
 if tool.startswith('get_all_'):return args.get('city') in c['cities'] and set(args)=={'city'}
 if tool=='get_flight_information':return args.get('departure_city') in c['cities'] and args.get('arrival_city') in c['cities'] and args.get('departure_city')!=args.get('arrival_city') and set(args)=={'departure_city','arrival_city'}
 if tool in ('search_calendar_events','get_day_calendar_events'):return True
 kind='hotels' if tool in HOTEL_READS else 'restaurants' if tool in RESTAURANT_READS else 'cars' if tool in CAR_READS else None
 if kind:
  field='hotel_name' if tool=='get_hotels_address' else 'hotel_names' if kind=='hotels' else 'restaurant_names' if kind=='restaurants' else 'company_name'
  value=args.get(field);values=[value] if isinstance(value,str) else value
  return set(args)=={field} and isinstance(values,list) and bool(values) and all(isinstance(x,str) and x in c['names'][kind] for x in values)
 return False
